# CyberShield — Automated Cybersecurity Log Analyzer

CyberShield is a desktop security tool that analyzes system/authentication logs and automatically flags suspicious activity — brute-force attacks, credential stuffing, suspicious IPs, unauthorized access, and off-hours logins — through a live Tkinter dashboard with Matplotlib visualizations.

Built to demonstrate practical, defensive security engineering: log parsing, rule-based threat detection, data analysis, and reporting — the kind of tooling used in SOC/Managed Detection & Response environments.

---

## Features

- **Multi-format log ingestion** — structured CSV logs or raw syslog-style text (parsed via regex)
- **Rule-based detection engine**
  - Brute-force attack detection (rolling time-window analysis)
  - Credential stuffing detection (many usernames from one IP)
  - Unauthorized access detection (success immediately after a failure burst)
  - Off-hours login flagging
- **Severity scoring** — Critical / High / Medium / Low
- **Live dashboard (Tkinter)** — summary cards, sortable findings table, dark SOC-style theme
- **Visual analytics (Matplotlib)** — severity breakdown, top offending IPs, login outcome ratio
- **One-click reporting** — exports timestamped CSV + plain-text executive summary

---

## Tech Stack

| Layer               | Technology                          |
|---------------------|--------------------------------------|
| Language            | Python 3.10+                        |
| Data Processing     | Pandas                              |
| Pattern Detection   | Regular Expressions (`re`)          |
| Time Analysis       | `datetime`, rolling time windows    |
| Data Storage        | CSV                                  |
| Visualization       | Matplotlib (embedded in Tkinter)    |
| GUI                 | Tkinter + ttk                       |

---

## Project Structure

```
CyberShield/
├── dashboard.py            # Main Tkinter GUI application (entry point)
├── log_analyzer.py         # Core detection engine (regex parsing + detection rules)
├── log_generator.py        # Generates realistic synthetic log data for demo/testing
├── report_generator.py     # Exports findings to CSV/TXT reports
├── data/
│   └── auth_log.csv        # Sample generated log data
├── reports/                # Exported analysis reports land here (gitignored contents)
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

---

## Getting Started

### 1. Clone the repo
```bash
git clone https://github.com/<your-username>/CyberShield.git
cd CyberShield
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```
> **Note:** Tkinter ships with most Python installations. On Ubuntu/Debian, if it's missing:
> `sudo apt-get install python3-tk`

### 3. Generate sample log data (optional — a sample is already included)
```bash
python3 log_generator.py
```
This creates `data/auth_log.csv` with ~500 simulated log entries, including embedded brute-force attacks, credential stuffing, and normal employee traffic — so you can demo detection immediately.

### 4. Launch the dashboard
```bash
python3 dashboard.py
```

### 5. Use it
1. Click **Load Log File** → select `data/auth_log.csv` (or your own CSV/log file)
2. Click **Run Analysis** → findings table + charts populate instantly
3. Click **Export Report** → saves a timestamped CSV + summary `.txt` to `reports/`

---

## Detection Logic (How It Works)

| Detection Rule | Logic |
|---|---|
| **Brute Force** | ≥5 failed logins from one IP within a rolling 10-minute window (sliding window algorithm) |
| **Credential Stuffing** | One IP attempts ≥5 distinct usernames — signature of automated attack tooling |
| **Unauthorized Access** | A `SUCCESS` login immediately follows ≥3 consecutive failures — strong signal of a compromised credential |
| **Off-Hours Login** | Successful login between 22:00–06:00, outside normal business hours |

Thresholds are configurable in `log_analyzer.py` via the `Thresholds` class — easy to tune sensitivity for a demo or a real dataset.

---

## Custom Log Format

If you're pointing this at your own **CSV** logs, use this schema:

```csv
timestamp,ip_address,username,status,event_type
2026-09-05 14:32:10,192.168.1.10,alice,SUCCESS,LOGIN
2026-09-05 14:33:02,45.83.12.201,admin,FAILED,LOGIN
```

For **raw syslog-style** text logs (e.g. SSH auth logs), the regex parser in `log_analyzer.py` extracts IP, username, and status automatically — extend `parse_raw_log_line()` for other log formats (Windows Event Log, Apache, etc.).

---

## Possible Extensions

- GeoIP lookup on offending IPs (flag logins from unexpected countries)
- Cross-reference IPs against threat-intel feeds (AbuseIPDB, VirusTotal API)
- PDF report export (mirrors a real consulting deliverable)
- Real-time log tailing (watch a live log file instead of static upload)
- SQLite backend for historical trend analysis across multiple audits



---

## Author

Built as a cybersecurity portfolio project demonstrating log analysis, threat detection logic, and security tooling development in Python.
