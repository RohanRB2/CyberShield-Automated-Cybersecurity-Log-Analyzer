"""
CyberShield - Sample Log Generator
------------------------------------
Generates a realistic synthetic auth/login log file (CSV) so the
analyzer and dashboard can be demoed without needing a real server.

Log fields:
    timestamp, ip_address, username, status, event_type

status      : SUCCESS | FAILED
event_type  : LOGIN | LOGOUT | SUDO | FILE_ACCESS
"""

import csv
import random
from datetime import datetime, timedelta

OUTPUT_FILE = "data/auth_log.csv"

# Pool of "normal" users and IPs (legitimate traffic)
NORMAL_USERS = ["alice", "bob", "carol", "dave", "erin"]
NORMAL_IPS = ["192.168.1.10", "192.168.1.11", "192.168.1.12",
              "192.168.1.13", "192.168.1.14"]

# A handful of "attacker" IPs that will hammer the system with
# failed logins (brute-force simulation) and try random usernames
ATTACKER_IPS = ["45.83.12.201", "185.220.101.7", "103.45.67.89"]
ATTACKER_GUESS_USERS = ["admin", "root", "administrator", "test",
                         "user", "guest", "oracle", "postgres"]

EVENT_TYPES = ["LOGIN", "LOGOUT", "SUDO", "FILE_ACCESS"]


def random_timestamp(base_time, max_offset_minutes=1440):
    """Return a random timestamp within `max_offset_minutes` of base_time."""
    offset = random.randint(0, max_offset_minutes)
    seconds = random.randint(0, 59)
    return base_time + timedelta(minutes=offset, seconds=seconds)


def generate_normal_traffic(rows, base_time, count=400):
    """Simulate legitimate employee login/logout/sudo activity."""
    for _ in range(count):
        user = random.choice(NORMAL_USERS)
        ip = random.choice(NORMAL_IPS)
        ts = random_timestamp(base_time)
        # Normal traffic mostly succeeds; occasional honest typo failure
        status = "SUCCESS" if random.random() > 0.03 else "FAILED"
        event = random.choices(EVENT_TYPES, weights=[50, 25, 15, 10])[0]
        rows.append([ts, ip, user, status, event])


def generate_brute_force_attack(rows, base_time, ip, target_user, count=25):
    """Simulate a brute-force attack: many failed logins in a short burst."""
    start = random_timestamp(base_time, max_offset_minutes=1000)
    for i in range(count):
        ts = start + timedelta(seconds=i * random.randint(2, 8))
        rows.append([ts, ip, target_user, "FAILED", "LOGIN"])
    # small chance the attacker eventually succeeds (weak password compromised)
    if random.random() > 0.5:
        rows.append([start + timedelta(seconds=count * 6 + 5), ip,
                     target_user, "SUCCESS", "LOGIN"])


def generate_credential_stuffing(rows, base_time, ip, count=15):
    """Simulate an attacker trying many different usernames from one IP."""
    start = random_timestamp(base_time, max_offset_minutes=1000)
    for i in range(count):
        user = random.choice(ATTACKER_GUESS_USERS)
        ts = start + timedelta(seconds=i * random.randint(3, 10))
        rows.append([ts, ip, user, "FAILED", "LOGIN"])


def main():
    random.seed(42)
    base_time = datetime.now() - timedelta(days=1)
    rows = []

    # 1. Normal day-to-day traffic
    generate_normal_traffic(rows, base_time, count=450)

    # 2. Brute-force attack on a single known user from one attacker IP
    generate_brute_force_attack(rows, base_time, ATTACKER_IPS[0], "admin", count=30)

    # 3. Another brute-force attack targeting a different employee account
    generate_brute_force_attack(rows, base_time, ATTACKER_IPS[1], "alice", count=18)

    # 4. Credential stuffing (many usernames, one IP)
    generate_credential_stuffing(rows, base_time, ATTACKER_IPS[2], count=20)

    # Sort chronologically like a real log file would be
    rows.sort(key=lambda r: r[0])

    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "ip_address", "username", "status", "event_type"])
        for r in rows:
            writer.writerow([r[0].strftime("%Y-%m-%d %H:%M:%S"), r[1], r[2], r[3], r[4]])

    print(f"[+] Generated {len(rows)} log entries -> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
