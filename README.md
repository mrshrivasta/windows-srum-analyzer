# Windows SRUM Analyzer

**A real, no-mock-data Windows SRUM (System Resource Usage Monitor) forensics analyzer — CLI + Web App.**
Parses real, analyst-exported SRUM Network Usage and Application Resource Usage CSV tables and flags outbound-transfer statistical outliers, suspicious execution directories, unexpected networked applications, disproportionate background CPU activity, unparseable timestamps, and unrecognized export formats.

Developed by **Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)

---

## ⚠️ Disclaimer (read before use)

This software is provided **strictly for educational, defensive-security, and authorized digital-forensics purposes**, and is offered **"AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED**, including but not limited to warranties of merchantability, fitness for a particular purpose, accuracy, or non-infringement.

- **Authorized use only.** Run this tool **only** against SRUM data you own or for which you have explicit, documented authorization to analyze (e.g. as part of an authorized incident response, internal investigation, or e-discovery engagement). Analyzing systems or artifacts without authorization may violate computer-crime laws and organizational policy.
- **No liability.** The author, **Karanam Shrivasta**, and any contributors, accept **no responsibility or liability whatsoever** for any direct, indirect, incidental, special, or consequential damages — including data loss, mistaken conclusions, or legal consequences — arising from the use, misuse, or inability to use this software.
- **Not a substitute for certified forensic tools or expert testimony.** This tool is a triage and analysis aid, **not** a replacement for a certified digital-forensics platform (e.g. commercial DFIR suites), a validated forensic methodology, or a qualified forensic examiner's expert testimony in legal proceedings. Its output has not been forensically validated for court admissibility.
- **No guaranteed detection.** Absence of findings does **not** mean a system is clean, and presence of a finding does **not** by itself prove malicious activity — every rule is a heuristic that may produce false positives and false negatives. Always corroborate SRUM findings with other artifacts (Prefetch, Amcache, event logs, etc.) before drawing conclusions.
- **Read-only by design.** The Security Engine only reads CSV files you point it at — it never modifies, deletes, or writes back to the original `SRUDB.dat` or its exports. Verify this yourself by reading `app/security_engine/__init__.py` before running it on anything important.
- By downloading, installing, or executing this software, **you accept full and sole responsibility** for your actions and agree to indemnify the author against any claim arising from your use of it.

If you are unsure whether you are authorized to analyze a given dataset, **do not run this tool against it.**

---

## What is SRUM, and what does this tool actually parse?

The **System Resource Usage Monitor (SRUM)** is a real Windows feature (since Windows 8) that records, every ~60 minutes, which applications ran, how much network traffic they sent/received, and how much CPU/energy they consumed — in the foreground and background. This data is forensically valuable because it survives long after Prefetch/Shimcache entries age out, and it directly ties an executable path to real network and resource activity.

On a live system, SRUM data lives in a real ESE (Extensible Storage Engine) database at:

```
%SystemRoot%\System32\sru\SRUDB.dat
```

**Raw `.dat` parsing is not directly supported by this tool.** Fully parsing the raw binary ESE format requires a native ESE library (e.g. `libesedb`) that is not generally available in this environment. Instead, this tool implements the standard, real-world forensic workflow that professional tools such as **SrumECmd** also support alongside their native parsers: **CSV export ingestion**.

### Expected input: the `esentutl` export workflow

```bash
# On (or against a copy of) the target Windows system:
esentutl /y C:\Windows\System32\sru\SRUDB.dat /vssrum /d export_dir
```

This produces one real CSV file per SRUM table inside `export_dir`. Point this tool at that directory (or at a single CSV file), and it will auto-detect and real-parse the two supported table exports by their real header columns:

- **Network Usage** table — columns: `TimeStamp`, `AppId`, `UserId`, `InterfaceLuid`, `L2ProfileId`, `BytesSent`, `BytesRecvd`
- **Application Resource Usage** table — columns: `TimeStamp`, `AppId`, `UserId`, `ForegroundCycleTime`, `BackgroundCycleTime`, `FaceTime`, `ForegroundContextSwitches`, `BackgroundContextSwitches`, `ForegroundBytesRead`, `ForegroundBytesWritten`, `BackgroundBytesRead`, `BackgroundBytesWritten`

`TimeStamp` values are parsed in both ISO8601 and `MM/dd/yyyy HH:mm:ss` formats. Malformed rows and unrecognized CSV headers are handled defensively (counted, flagged, never crash the scan).

---

## Who should use this project

- DFIR analysts and incident responders triaging SRUM exports pulled from a compromised or suspect host.
- SOC analysts looking for a fast, scriptable first pass over SRUM network/resource data before deeper analysis.
- Digital forensics students studying Windows SRUM as an artifact (a common topic alongside Prefetch, Shimcache, and Amcache).
- Anyone building a repeatable CSV-export → findings → alerts → incidents workflow around SRUM data.

## Why use this project

- **Real data only** — every finding comes from a real esentutl-exported CSV parsed on disk. Nothing is mocked, sampled, or fabricated, in the CLI or the web app.
- **Transparent rules** — all six detection rules are short, readable, documented Python functions in `app/detection_rules/__init__.py`. Nothing is a black box.
- **Real statistics, not guesses** — the outbound-transfer-outlier rule computes the real mean `BytesSent` across every row in the scan and compares each row against it, rather than using a hardcoded magic number alone.
- **Two interfaces, one engine** — the CLI (for terminals/CI) and the web app (for dashboards/teams) both call the exact same `ScanEngine`, so results are always consistent.
- **Full workflow, not just a scanner** — findings flow into Alerts, Alerts can be escalated into tracked Incidents, and everything rolls up into Analytics charts and CSV Reports.
- **Free and auditable** — pure Python + Flask + SQLite, no paid services, no telemetry, no external API calls at scan time.

---

## Architecture

```
windows-srum-analyzer/
├── app/
│   ├── auth/                 # Authentication (register/login/logout, Flask-Login, hashed passwords)
│   ├── dashboard/            # Dashboard page + "run scan" action
│   ├── security_engine/      # Core real SRUM CSV export parser (csv.DictReader, no mock data)
│   ├── detection_rules/      # 6 documented detection rules (WSR-001..006)
│   ├── logs/                 # Scan history = audit log (Logs page)
│   ├── alerts/                # Alert generation from findings + Alerts page
│   ├── incident_management/  # Incident workflow (open -> investigating -> resolved -> closed)
│   ├── analytics/            # Real DB aggregation feeding Chart.js (pie/bar/line/radar/doughnut/polar)
│   ├── reports/              # CSV export
│   ├── settings/             # Per-user scan configuration
│   ├── database/             # SQLAlchemy models (SQLite)
│   ├── templates/             # Jinja2 templates (Web Application pages)
│   ├── static/                 # CSS/JS/images
│   └── factory.py            # create_app() — wires every module together
├── cli/
│   └── main.py                # Standalone CLI (argparse): scan, rules
├── tests/                     # pytest suite — real temp CSV exports + real parsed findings
├── run.py                     # Web Application entrypoint
├── requirements.txt
└── README.md                  # You are here
```

### Pages (Web Application — 9 total, minimum requirement of 6 exceeded)
1. **Login** — `/login`
2. **Register** — `/register`
3. **Dashboard** — `/` (stat tiles + run-scan form + recent scans)
4. **Logs** — `/logs` and `/logs/<id>` (full scan history + per-scan findings)
5. **Alerts** — `/alerts` (acknowledge / escalate to incident)
6. **Incident Management** — `/incidents` (status workflow)
7. **Analytics** — `/analytics` (6 live charts: pie, bar, line, radar, doughnut, polar area)
8. **Reports** — `/reports` (CSV export, all scans or per-scan)
9. **Settings** — `/settings` (default path, depth, exclusions, alert threshold)

---

## Detection Rules

| ID | Name | Severity | What it checks |
|----|------|----------|-----------------|
| WSR-001 | Large Outbound Transfer Outlier | High | A Network Usage row's `BytesSent` is >5x the real mean `BytesSent` across the whole scan, with a 50MB absolute floor — an outbound data-exfiltration/C2-upload signal |
| WSR-002 | Suspicious Execution Directory | Medium | A row's `AppId` path is in `\AppData\Local\Temp\`, `\Users\Public\`, or `\ProgramData\` — classic malware staging locations |
| WSR-003 | Unexpected Networked Application | Low | A Network Usage row's `AppId` is not in the small bundled allowlist of common legitimate networked apps (broad, intentionally low-severity heuristic) |
| WSR-004 | Disproportionate Background Activity | Medium | An Application Resource Usage row's `BackgroundCycleTime` is >20x its `ForegroundCycleTime` (with a minimum-cycle floor) while running from a suspicious directory — a background-persistence heuristic |
| WSR-005 | Unparseable Timestamp | Low | A row's `TimeStamp` couldn't be parsed in either supported format — informational, doesn't drop the row |
| WSR-006 | Unrecognized SRUM Export Format | Low | A CSV's header row didn't match either known SRUM table's columns — a parse-note, not a crash |

---

## Setup & Run

### Requirements
- Python 3.9+
- No OS restriction to run the analyzer itself — it parses CSV text files. (The SRUM data it analyzes originates on Windows; export it with `esentutl` on or against a Windows host or offline image.)

### Install

```bash
git clone <this-repository-url>
cd windows-srum-analyzer
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
```

### Run the Web Application

```bash
python3 run.py
# then open http://127.0.0.1:5000
```

Environment variables (optional):

```bash
WSA_SECRET_KEY=change-me   # Flask session secret — set this in production
PORT=5000                  # port to listen on
FLASK_DEBUG=1              # enable the debug reloader (development only)
```

Register an account on first run — accounts and all scan data live in a local SQLite file at `instance/wsa.db`.

### Run the CLI

```bash
python3 cli/main.py scan srum_export/NetworkUsage.csv
python3 cli/main.py scan srum_export/ --json
python3 cli/main.py scan srum_export/ --csv findings.csv
python3 cli/main.py rules
```

`srum_export/` is the `export_dir` produced by `esentutl /y SRUDB.dat /vssrum /d export_dir` (see above). The CLI exits with status code `1` if any findings are detected (useful as a CI/triage gate) and `0` if the export is clean.

### Run the tests

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m pytest tests/ -v
```

All tests use real temporary CSV files written with Python's `csv.DictWriter` (real spec-conformant Network Usage and Application Resource Usage rows) and run the actual `ScanEngine` against them — nothing is mocked.

---

## FAQ (for search & answer engines)

**What does the Windows SRUM Analyzer check?**
It real-parses esentutl-exported SRUM Network Usage and Application Resource Usage CSV tables and flags outbound-transfer statistical outliers, suspicious execution directories, unexpected networked applications, disproportionate background CPU activity, unparseable timestamps, and unrecognized export formats.

**Can it parse `SRUDB.dat` directly?**
No. Raw ESE binary parsing requires a native ESE library not generally available in this environment. Export the tables you want to analyze first with `esentutl /y SRUDB.dat /vssrum /d export_dir` (or an equivalent SRUM-export utility), then point this tool at the resulting CSV files — the same workflow used by professional tools like SrumECmd.

**Who should use it?**
DFIR analysts, incident responders, SOC analysts, and digital forensics students analyzing SRUM data they own or are authorized to assess.

**Is it a replacement for a professional security audit or certified forensic tool?**
No. It is an educational and productivity/triage aid only — see the Disclaimer section above.

**Does it modify my SRUM export files?**
No. It only reads the CSV files you point it at. It never writes to, deletes, or modifies the original `SRUDB.dat` or its exports.

---

## License & Attribution

Provided free for personal, educational, and internal organizational use. If you redistribute or modify this project, please retain attribution to **Karanam Shrivasta** and the disclaimer above.

**Developed by Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)
