"""
Configuration module for File Integrity Monitoring and Tampering Detection System.
Defines global paths, constants, security heuristic rules, and redaction patterns.
"""
import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent

# Serverless / Read-Only Environment Handling (e.g., Vercel, AWS Lambda)
IS_SERVERLESS = bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))

if IS_SERVERLESS:
    TEMP_DIR = Path("/tmp")
    VAULT_DIR = TEMP_DIR / ".fim_vault"
    DB_PATH = TEMP_DIR / "fim_database.sqlite3"
    REPORTS_DIR = TEMP_DIR / "generated_reports"

    # Safely create writable temp directories
    try:
        VAULT_DIR.mkdir(parents=True, exist_ok=True)
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    # Copy pre-seeded database to writable /tmp on cold start if needed
    src_db = BASE_DIR / "fim_database.sqlite3"
    if src_db.exists() and not DB_PATH.exists():
        import shutil
        try:
            shutil.copy2(src_db, DB_PATH)
        except Exception:
            pass

    # Copy pre-existing baseline snapshots to /tmp/.fim_vault
    src_vault = BASE_DIR / ".fim_vault"
    if src_vault.exists():
        import shutil
        try:
            for snap in src_vault.iterdir():
                if snap.is_file() and not (VAULT_DIR / snap.name).exists():
                    shutil.copy2(snap, VAULT_DIR / snap.name)
        except Exception:
            pass
else:
    VAULT_DIR = BASE_DIR / ".fim_vault"
    DB_PATH = BASE_DIR / "fim_database.sqlite3"
    REPORTS_DIR = BASE_DIR / "generated_reports"

    # Ensure essential directories exist safely
    try:
        VAULT_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    try:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

# Persistent Database Settings (Supabase / PostgreSQL with fallback to SQLite)
DATABASE_URL = (
    os.environ.get("SUPABASE_DB_URL")
    or os.environ.get("DATABASE_URL")
    or os.environ.get("POSTGRES_URL")
    or ""
).strip()

# Security & Session Secrets
SECRET_KEY = os.environ.get("SECRET_KEY", "fim-sentinel-fallback-session-key-849102")
FIM_ADMIN_PASSWORD = os.environ.get("FIM_ADMIN_PASSWORD", "").strip()

# Integrity Status Constants
STATUS_UNCHANGED = "UNCHANGED"
STATUS_MODIFIED = "MODIFIED"
STATUS_MISSING = "MISSING"

# Performance and Limits
CHUNK_SIZE = 65536                  # 64 KB single-pass read chunk
MAX_SNAPSHOT_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB maximum for baseline text snapshots
MAX_UPLOAD_SIZE_BYTES = 15 * 1024 * 1024    # 15 MB maximum file upload limit
DEBOUNCE_INTERVAL_SEC = 0.75        # 750 ms debounce delay for Windows atomic writes
MAX_DIFF_LINES_FOR_AI = 150         # Diff line cutoff to prevent token exhaustion and high latency
FILE_LOCK_RETRIES = 5               # Retries when encountering WinError 32
FILE_LOCK_RETRY_DELAY = 0.15        # Delay in seconds between lock retries

# Threat Heuristic Rules (Deterministic static pattern matching)
HEURISTIC_RULES = {
    "HIGH": [
        {
            "id": "HIGH_PRIV_ESC",
            "name": "Privilege Escalation & Permission Tampering",
            "pattern": r"(?i)(chmod\s+(?:[0-7]{3,4}|[ugoarwx+-=]+)|chown\s+|admin\s*=\s*(?:true|1|yes)|root\s*:\s*root|sudoers|RUNAS\s+/user:|grant\s+all\s+privileges|takeown\s+/f|icacls\s+.*grant.*:F)",
            "description": "Modification grants superuser privileges or sets overly permissive file permissions.",
            "score": 35
        },
        {
            "id": "HIGH_FIREWALL_DISABLE",
            "name": "Defense Evasion & Security Disablement",
            "pattern": r"(?i)(DisableRealtimeMonitoring|Set-MpPreference|netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off|ufw\s+disable|iptables\s+-F|systemctl\s+stop\s+(?:firewalld|auditd|clamav)|sc\s+stop\s+(?:WinDefend|MpsSvc))",
            "description": "Attempt to disable or weaken host firewalls, antivirus, or defensive monitoring services.",
            "score": 40
        },
        {
            "id": "HIGH_CREDENTIAL_LEAK",
            "name": "Hardcoded Secret or Private Key Addition",
            "pattern": r"(?i)(-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----|(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|db_password)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{8,}['\"])",
            "description": "Detected hardcoded cryptographic private keys, high-entropy secrets, or sensitive API credentials.",
            "score": 30
        },
        {
            "id": "HIGH_REVERSE_SHELL",
            "name": "Suspicious Network Binding or Remote Shell",
            "pattern": r"(?i)(nc(?:\.exe)?\s+-[le]|bash\s+-i\s+>&|powershell(?:\.exe)?\s+.*-(?:enc|encodedcommand|w\s+hidden)|curl\s+https?://[^\s]+\s*\|\s*(?:bash|sh|cmd)|Invoke-Expression|IEX\s*\(|bind\(\s*['\"]0\.0\.0\.0['\"])",
            "description": "Addition of reverse shells, hidden execution flags, remote pipe-to-shell, or wildcard network listeners.",
            "score": 40
        },
        {
            "id": "HIGH_CRITICAL_HOST_OVERRIDE",
            "name": "Critical Host or System DNS Tampering",
            "pattern": r"(?i)(127\.0\.0\.1\s+[a-z0-9\-\.]*(?:microsoft|google|virustotal|update|defender)|0\.0\.0\.0\s+[a-z0-9\-\.]*(?:update|security))",
            "description": "Altering DNS host mapping to hijack or sinkhole critical security and update domains.",
            "score": 35
        }
    ],
    "MEDIUM": [
        {
            "id": "MED_ENV_MOD",
            "name": "Environment Variable Alteration",
            "pattern": r"(?i)(export\s+[A-Z_]+=|setx\s+[A-Z_]+\s+|os\.environ\[['\"][A-Z_]+['\"]\]\s*=|\.env(?:\.local)?\s+modified)",
            "description": "Modification of system or application runtime environment variables.",
            "score": 15
        },
        {
            "id": "MED_OUTBOUND_ENDPOINT",
            "name": "New Outbound Endpoint / External URL",
            "pattern": r"(?i)(https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?::[0-9]+)?|webhook\.site|ngrok\.io|pastebin\.com|discord\.com/api/webhooks)",
            "description": "Addition of direct IP URLs, ngrok tunnels, webhooks, or unverified external paste services.",
            "score": 20
        },
        {
            "id": "MED_MASS_DELETION",
            "name": "High-Volume Content Deletion",
            "pattern": r"",  # Handled dynamically by diff metrics
            "description": "Over 35% of existing file lines or more than 40 lines were removed in a single revision.",
            "score": 20
        },
        {
            "id": "MED_DATABASE_QUERY_TAMPER",
            "name": "Raw SQL Execution / Drop Table",
            "pattern": r"(?i)(DROP\s+TABLE|TRUNCATE\s+TABLE|DELETE\s+FROM\s+[a-z_]+\s*(?:;|$)|ALTER\s+TABLE\s+.*DROP)",
            "description": "Destructive or schema-altering SQL modifications detected.",
            "score": 20
        }
    ],
    "LOW": [
        {
            "id": "LOW_CONFIG_TWEAK",
            "name": "General Configuration & Variable Adjustment",
            "pattern": r"(?i)(?:timeout|retries|max_workers|port|buffer_size|debug|verbose)\s*[:=]",
            "description": "Standard tuning of application operational parameters.",
            "score": 5
        },
        {
            "id": "LOW_FORMATTING",
            "name": "Formatting & Cosmetic Modification",
            "pattern": r"^\s*$",
            "description": "Line modifications consisting of indentation, whitespace, or empty line additions.",
            "score": 1
        }
    ]
}

# Privacy & Secret Sanitization Patterns (Regexes to mask before sending to AI)
REDACTION_PATTERNS = [
    (r"(?i)(['\"]?(?:api[_-]?key|apikey|secret|token|password|passwd|pwd|auth)[\"']?\s*[:=]\s*['\"])([^'\"\n]{4,})(['\"])",
     r"\g<1>[REDACTED_SECRET]\g<3>"),
    (r"(AIza[0-9A-Za-z-_]{35})", r"[REDACTED_GOOGLE_API_KEY]"),
    (r"(sk-[a-zA-Z0-9]{20,T3BlbkFJ[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_-]{40,})", r"[REDACTED_OPENAI_KEY]"),
    (r"(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)", r"[REDACTED_PRIVATE_KEY]"),
    (r"(Bearer\s+[A-Za-z0-9_\-\.]{20,})", r"Bearer [REDACTED_BEARER_TOKEN]"),
    (r"(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})", r"[REDACTED_GITHUB_TOKEN]"),
    (r"(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})", r"[REDACTED_SLACK_TOKEN]"),
    (r"(AKIA[0-9A-Z]{16})", r"[REDACTED_AWS_ACCESS_KEY]"),
    (r"((?:[0-9]{1,3}\.){3}[0-9]{1,3})", r"[REDACTED_IP_ADDR]"),
]

# System Novelty & Architecture Statement
NOVELTY_STATEMENT = (
    "The system introduces a multi-tiered File Integrity & Threat Triage architecture "
    "that bridges low-level cryptographic verification with contextual reasoning. Unlike conventional "
    "FIMs (which only report binary pass/fail hash mismatches), this system integrates: (1) dual-primitive "
    "cryptographic baseline validation (SHA-2 + SHA-3 sponge resistance), (2) a local delta-reconstruction "
    "engine for syntactic diffing, (3) a deterministic rule-based threat heuristic for permission and "
    "configuration tampering, and (4) privacy-sanitized, contextual AI triage to explain operational "
    "impact and remediation strategies in real time."
)
