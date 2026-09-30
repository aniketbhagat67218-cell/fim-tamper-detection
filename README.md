# File Integrity Monitoring and Tampering Detection System (FIM)

A high-performance, modular desktop cybersecurity application engineered in Python with **CustomTkinter** and **SQLite (WAL mode)**. The system provides real-time file integrity monitoring, dual-primitive cryptographic baseline validation, local delta reconstruction, deterministic heuristic threat triage, privacy-sanitized AI advisory, and automated forensic audit reporting.

---

## Enhanced Novelty Statement
> *"The system introduces a multi-tiered File Integrity & Threat Triage architecture that bridges low-level cryptographic verification with contextual reasoning. Unlike conventional FIMs (which only report binary pass/fail hash mismatches), this system integrates: (1) dual-primitive cryptographic baseline validation (SHA-2 + SHA-3 sponge resistance), (2) a local delta-reconstruction engine for syntactic diffing, (3) a deterministic rule-based threat heuristic for permission and configuration tampering, and (4) privacy-sanitized, contextual AI triage to explain operational impact and remediation strategies in real time."*

---

## Architectural Highlights & Critical Flaw Solutions

| Flaw / Edge Case | Conventional Vulnerability | FIM Architectural Solution |
| :--- | :--- | :--- |
| **Flaw 1: Missing Baseline Content Trap** | Hashes are one-way; diffing against a hash is impossible. | **Secure Snapshot Vault (`.fim_vault/`)**: Byte-for-byte baseline copies (<10 MB) are preserved to feed `difflib.unified_diff` on tamper detection. |
| **Flaw 2: Watchdog Event Flooding & File Locks** | Atomic saves trigger 3–5 rapid events and `WinError 32` file locks. | **750ms Debouncer + Exponential Lock Retry**: Coalesces bursts, retries with backoff, and verifies hash difference before alerting. |
| **Flaw 3: GUI & SQLite Thread Locking** | Watchdog callbacks update GUI directly, triggering Tkinter crashes. | **Thread-Safe Queue (`queue.Queue`) & SQLite WAL**: Background threads post to queue; UI polls via `root.after(100)`. |
| **Flaw 4: Inefficient Dual Hashing** | Reading files twice for SHA-256 and SHA-3-256 burns disk I/O. | **Single-Pass 64 KB Stream**: Both `hashlib.sha256()` and `hashlib.sha3_256()` update concurrently from a single chunk stream. |
| **Flaw 5: Privacy Leaks to AI** | Sending full configuration diffs leaks API keys and passwords. | **Pre-Flight Regex Sanitizer**: Redacts secrets to `[REDACTED_SECRET]` and caps diffs at 150 lines before AI dispatch. |
| **Flaw 6: Directory vs. File Monitoring** | Watchdog `Observer` cannot watch loose files efficiently. | **Parent Directory Watcher + In-Memory Filter**: Watches parent directories and instantly filters events against the active watch-set. |

---

## Project Structure

```text
PROJECT MDC ALPHA/
│
├── app.py                      # Application entry point (CustomTkinter App & Event Loop)
├── config.py                   # Global constants, paths, risk patterns, and redaction rules
├── requirements.txt            # Locked dependency specifications
├── README.md                   # Comprehensive system documentation
├── fim_database.sqlite3        # SQLite database (auto-generated in WAL mode)
│
├── core/
│   ├── __init__.py
│   ├── hasher.py               # Single-pass dual hashing (SHA-256 & SHA-3-256) via 64 KB chunks
│   ├── vault.py                # Local snapshot storage (.fim_vault/) for delta reconstruction
│   ├── comparator.py           # Unified diffing (difflib) and binary delta inspection
│   ├── risk_analyzer.py        # Deterministic security heuristic rules engine (Low/Medium/High)
│   ├── ai_advisor.py           # Privacy sanitizer & structured AI dispatch (Gemini & OpenAI)
│   └── monitor.py              # Watchdog directory observer with 750ms debouncer & lock-retry
│
├── database/
│   ├── __init__.py
│   └── db_manager.py           # Thread-safe SQLite manager in WAL mode
│
├── ui/
│   ├── __init__.py
│   ├── theme.py                # Cyber dark palette (#0D1117 slate & neon accents)
│   ├── components/
│   │   ├── __init__.py
│   │   ├── stat_card.py        # Metric card with values and trend indicators
│   │   ├── data_table.py       # Table with column layout, sorting, and status badges
│   │   └── diff_viewer.py      # Color-coded diff syntax viewer with line numbers
│   └── views/
│       ├── __init__.py
│       ├── dashboard_view.py   # System overview, stats, live event activity stream
│       ├── scanner_view.py     # File/folder picker, preview hashes, baseline vaulting
│       ├── monitored_view.py   # Active asset inventory, manual verify, update baseline
│       ├── diff_view.py        # Deep-dive change analysis, heuristics card, AI advisory
│       ├── history_view.py     # Searchable audit log with risk filter and report export
│       ├── reports_view.py     # Generated report manager with browser preview
│       └── settings_view.py    # Vault limits, debounce timer, and API key management
│
├── reports/
│   ├── __init__.py
│   └── report_generator.py     # Standalone printable HTML and Markdown report generator
│
├── generated_reports/          # Directory containing generated audit documents
├── .fim_vault/                 # Secure local vault storing trusted baseline snapshots
│
└── tests/
    ├── __init__.py
    ├── test_hasher.py          # Dual hashing accuracy tests
    ├── test_vault.py           # Snapshot vaulting and retrieval tests
    ├── test_comparator.py      # Unified diff and binary detection tests
    ├── test_risk_analyzer.py   # Heuristic rule detection validation
    └── test_sanitizer.py       # Secret redaction & privacy tests
```

---

## Installation & Setup

### Prerequisites
- Python 3.10+ (tested on Python 3.14 on Windows)
- Required packages:
  ```powershell
  pip install -r requirements.txt
  ```

### Running the Application
Launch the desktop application via:
```powershell
python app.py
```

---

## Feature Walkthrough

### 1. Security Operations Dashboard
- **Live Metrics**: Displays total monitored files, clean assets, tampering alerts, and watchdog engine state.
- **Real-Time Controls**: Start or stop real-time background filesystem monitoring with one click.
- **Forensic Activity Feed**: Live event log showing timestamp, target asset, event type, and risk severity.

### 2. Asset Discovery & Baseline Vaulting (`scanner_view.py`)
- Select individual files or entire folders with extension filters (e.g. `.py, .env, .json, .ini, .yaml, .conf`).
- Calculates streaming dual-hashes in a background worker thread.
- Automatically stores trusted baseline copies inside `.fim_vault/` for future syntactical diffing.

### 3. Change Analysis & Visual Diff (`diff_view.py`)
- **Dual Fingerprints**: Compares baseline vs current SHA-256 and SHA-3-256.
- **Syntax Diff Console**: Color-coded line diff with line numbers:
  - Green (`+`): Inserted lines
  - Red (`-`): Deleted lines
  - Gray: Unchanged context lines
- **Binary Support**: Displays size deltas, timestamp shifts, and hash changes for compiled/binary assets.

### 4. Deterministic Heuristic Risk Engine (`risk_analyzer.py`)
- Operates 100% offline without API keys:
  - **High Risk**: Privilege escalation (`chmod 777`, `admin=true`), firewall/AV disablement (`DisableRealtimeMonitoring`, `ufw disable`, `netsh`), hardcoded credentials (`BEGIN PRIVATE KEY`, `api_key=`), reverse shells (`nc -e`, `0.0.0.0` bindings).
  - **Medium Risk**: Environment alterations (`os.environ`), outbound URLs/IPs, massive content deletions (>35% or >40 lines).
  - **Low Risk**: General configuration tuning and formatting changes.
- Clear UI disclaimer indicating heuristic risk estimation.

### 5. Privacy-Preserving AI Threat Advisor (`ai_advisor.py`)
- **Local Secret Sanitization**: Redacts passwords, bearer tokens, AWS keys, Google API keys, OpenAI keys, and IP addresses to `[REDACTED_SECRET]` before transmission.
- **Diff Cutoff**: Caps diff snippets at 150 lines to conserve tokens and reduce latency.
- **Supported Providers**: Google Gemini and OpenAI.
- **Offline Resiliency**: If no API key is set or the network is unavailable, generates structured guidance using the local deterministic heuristics.

### 6. Forensic Audit Reports (`reports/report_generator.py`)
- Generates professional HTML reports formatted with cybersecurity dark theme and clean print media styles (suitable for exporting to PDF via browser print).
- Generates Markdown reports for compliance documentation and version control audit logs.

---

## Running Automated Tests

Execute the test suite to verify cryptographic hashing, snapshot retention, unified diffs, heuristic pattern matching, and secret sanitization:
```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```
