"""
CyberShield - Report Generator
------------------------------------
Exports analysis findings and summary statistics to CSV report files
inside the reports/ folder, timestamped so each run is preserved.
"""

import os
from datetime import datetime


def export_findings_csv(findings_df, output_dir="reports"):
    """Save the findings DataFrame to a timestamped CSV file."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"cybershield_report_{timestamp}.csv")
    findings_df.to_csv(filepath, index=False)
    return filepath


def export_summary_txt(stats, output_dir="reports"):
    """Save a human-readable plain-text executive summary."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"cybershield_summary_{timestamp}.txt")

    lines = [
        "=" * 55,
        "  CyberShield - Security Log Analysis Summary",
        "=" * 55,
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"Total Log Events Analyzed : {stats['total_events']}",
        f"Successful Logins         : {stats['total_success']}",
        f"Failed Logins             : {stats['total_failed']}",
        f"Unique IP Addresses       : {stats['unique_ips']}",
        f"Total Findings Flagged    : {stats['total_findings']}",
        "",
        "Findings by Severity:",
    ]
    for severity, count in stats.get("severity_counts", {}).items():
        lines.append(f"  - {severity}: {count}")

    lines.append("")
    lines.append("Top Offending IP Addresses (by failed attempts):")
    for ip, count in stats.get("top_offending_ips", {}).items():
        lines.append(f"  - {ip}: {count} failed attempts")

    lines.append("=" * 55)

    with open(filepath, "w") as f:
        f.write("\n".join(lines))

    return filepath
