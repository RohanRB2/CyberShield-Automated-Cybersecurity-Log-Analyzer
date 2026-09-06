"""
CyberShield - Log Analyzer Engine
------------------------------------
Loads log data (CSV, or raw text using regex extraction), then applies
detection rules to flag suspicious activity:

  - Brute-force attempts   : many FAILED logins from one IP in a short window
  - Credential stuffing    : one IP trying many different usernames
  - Suspicious IPs         : IPs whose failure rate is abnormally high
  - Unauthorized access    : SUCCESS immediately following a failure burst
    (classic "attacker finally guessed it" pattern)
  - Off-hours activity     : logins outside typical working hours (flagged, lower severity)

Produces a clean pandas DataFrame of findings that the GUI / report
layer can consume directly.
"""

import re
import pandas as pd
from datetime import timedelta

# ---------------------------------------------------------------------------
# Regex patterns (used when parsing raw/unstructured log lines, e.g. syslog
# style: "Jan 21 04:52:11 server sshd[1234]: Failed password for admin
# from 45.83.12.201 port 51422 ssh2")
# ---------------------------------------------------------------------------
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER_REGEX = re.compile(r"for (invalid user )?(\w+) from")
STATUS_REGEX = re.compile(r"(Failed|Accepted) password")
TIMESTAMP_REGEX = re.compile(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}")


# ---------------------------------------------------------------------------
# Detection thresholds — tweak these to tune sensitivity
# ---------------------------------------------------------------------------
class Thresholds:
    BRUTE_FORCE_FAILS = 5          # failed attempts...
    BRUTE_FORCE_WINDOW_MIN = 10    # ...within this many minutes -> brute force
    CRED_STUFF_UNIQUE_USERS = 5    # distinct usernames from one IP -> stuffing
    HIGH_RISK_FAILS = 15           # failures from one IP -> "high risk" severity
    OFF_HOURS_START = 22           # 22:00
    OFF_HOURS_END = 6              # 06:00


def load_csv_log(path):
    """Load a structured CSV log (timestamp, ip_address, username, status, event_type)."""
    df = pd.read_csv(path, parse_dates=["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


def parse_raw_log_line(line):
    """Extract structured fields from a raw syslog-style line using regex."""
    ip_match = IP_REGEX.search(line)
    user_match = USER_REGEX.search(line)
    status_match = STATUS_REGEX.search(line)

    if not (ip_match and status_match):
        return None

    return {
        "ip_address": ip_match.group(0),
        "username": user_match.group(2) if user_match else "unknown",
        "status": "SUCCESS" if status_match.group(1) == "Accepted" else "FAILED",
    }


def parse_raw_log_file(path):
    """Parse an entire raw text log file into a DataFrame."""
    records = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            parsed = parse_raw_log_line(line)
            if parsed:
                records.append(parsed)
    return pd.DataFrame(records)


# ---------------------------------------------------------------------------
# Detection functions
# ---------------------------------------------------------------------------
def detect_brute_force(df, t=Thresholds):
    """
    Flag IP addresses with >= BRUTE_FORCE_FAILS failed logins within a
    rolling BRUTE_FORCE_WINDOW_MIN-minute window.
    """
    findings = []
    failed = df[df["status"] == "FAILED"].copy()

    for ip, group in failed.groupby("ip_address"):
        group = group.sort_values("timestamp")
        timestamps = group["timestamp"].tolist()

        window_start = 0
        for window_end in range(len(timestamps)):
            # shrink window from the left until it's within the time limit
            while timestamps[window_end] - timestamps[window_start] > timedelta(minutes=t.BRUTE_FORCE_WINDOW_MIN):
                window_start += 1
            attempts_in_window = window_end - window_start + 1
            if attempts_in_window >= t.BRUTE_FORCE_FAILS:
                findings.append({
                    "type": "Brute Force Attack",
                    "severity": "High" if attempts_in_window >= t.HIGH_RISK_FAILS else "Medium",
                    "ip_address": ip,
                    "username": group.iloc[window_end]["username"],
                    "details": f"{attempts_in_window} failed logins within "
                               f"{t.BRUTE_FORCE_WINDOW_MIN} minutes",
                    "timestamp": timestamps[window_end],
                })
                break  # one finding per IP is enough, avoid duplicate spam

    return findings


def detect_credential_stuffing(df, t=Thresholds):
    """Flag IPs that tried many *different* usernames (credential stuffing)."""
    findings = []
    failed = df[df["status"] == "FAILED"]

    for ip, group in failed.groupby("ip_address"):
        unique_users = group["username"].nunique()
        if unique_users >= t.CRED_STUFF_UNIQUE_USERS:
            findings.append({
                "type": "Credential Stuffing",
                "severity": "High",
                "ip_address": ip,
                "username": f"{unique_users} distinct usernames",
                "details": f"IP attempted {unique_users} different usernames "
                            f"({group['username'].nunique()} unique) — automated attack pattern",
                "timestamp": group["timestamp"].max(),
            })

    return findings


def detect_unauthorized_access(df, t=Thresholds):
    """
    Flag cases where an IP had a burst of failures immediately followed
    by a SUCCESS — a strong signal the account was actually compromised.
    """
    findings = []
    for ip, group in df.groupby("ip_address"):
        group = group.sort_values("timestamp").reset_index(drop=True)
        fail_streak = 0
        for i, row in group.iterrows():
            if row["status"] == "FAILED":
                fail_streak += 1
            elif row["status"] == "SUCCESS" and fail_streak >= 3:
                findings.append({
                    "type": "Unauthorized Access (Post Brute-Force)",
                    "severity": "Critical",
                    "ip_address": ip,
                    "username": row["username"],
                    "details": f"Login SUCCEEDED after {fail_streak} consecutive "
                               f"failed attempts — account likely compromised",
                    "timestamp": row["timestamp"],
                })
                fail_streak = 0
            else:
                fail_streak = 0
    return findings


def detect_off_hours_activity(df, t=Thresholds):
    """Flag successful logins occurring outside normal business hours."""
    findings = []
    success = df[df["status"] == "SUCCESS"].copy()
    success["hour"] = success["timestamp"].dt.hour

    off_hours = success[
        (success["hour"] >= t.OFF_HOURS_START) | (success["hour"] < t.OFF_HOURS_END)
    ]
    for _, row in off_hours.iterrows():
        findings.append({
            "type": "Off-Hours Login",
            "severity": "Low",
            "ip_address": row["ip_address"],
            "username": row["username"],
            "details": f"Successful login at {row['timestamp'].strftime('%H:%M')} "
                        f"(outside normal hours)",
            "timestamp": row["timestamp"],
        })
    return findings


def run_full_analysis(df, t=Thresholds):
    """Run all detection rules and return a single findings DataFrame."""
    all_findings = []
    all_findings += detect_brute_force(df, t)
    all_findings += detect_credential_stuffing(df, t)
    all_findings += detect_unauthorized_access(df, t)
    all_findings += detect_off_hours_activity(df, t)

    findings_df = pd.DataFrame(all_findings)
    if not findings_df.empty:
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        findings_df["severity_rank"] = findings_df["severity"].map(severity_order)
        findings_df = findings_df.sort_values("severity_rank").drop(columns="severity_rank")
        findings_df = findings_df.reset_index(drop=True)
    return findings_df


def compute_summary_stats(df, findings_df):
    """Compute headline stats used in the dashboard summary panel."""
    total_events = len(df)
    total_failed = len(df[df["status"] == "FAILED"])
    total_success = len(df[df["status"] == "SUCCESS"])
    unique_ips = df["ip_address"].nunique()

    severity_counts = (
        findings_df["severity"].value_counts().to_dict() if not findings_df.empty else {}
    )

    top_offending_ips = (
        df[df["status"] == "FAILED"]["ip_address"].value_counts().head(5).to_dict()
    )

    return {
        "total_events": total_events,
        "total_failed": total_failed,
        "total_success": total_success,
        "unique_ips": unique_ips,
        "total_findings": len(findings_df),
        "severity_counts": severity_counts,
        "top_offending_ips": top_offending_ips,
    }


if __name__ == "__main__":
    # Quick standalone test
    df = load_csv_log("data/auth_log.csv")
    findings = run_full_analysis(df)
    stats = compute_summary_stats(df, findings)
    print(stats)
    print(findings)
