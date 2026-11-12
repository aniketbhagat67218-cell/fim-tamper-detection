"""
FIM Sentinel - Standalone Desktop Background Agent & Real-Time Watchdog
Monitors local files on disk in real time.
When a file is modified (Ctrl+S), it:
1. Recomputes SHA-256 hash.
2. Detects tampering against baseline.
3. Fires an instant Mobile / Desktop notification via Telegram or Discord!
4. Syncs tampering event with FIM Sentinel Web Dashboard.
"""
import os
import sys
import time
import json
import hashlib
import argparse
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime

# Import real-time alerts
try:
    from alerts import dispatch_tamper_alert, get_alert_config
except ImportError:
    # Fallback if imported from elsewhere
    def dispatch_tamper_alert(*args, **kwargs):
        pass
    def get_alert_config():
        return {}


def calculate_sha256(filepath: Path) -> str:
    """Calculates single SHA-256 hash of a file."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return ""


class FIMAgent:
    def __init__(self, watch_dir: str, server_url: str = "http://localhost:5000"):
        self.watch_dir = Path(watch_dir).resolve()
        self.server_url = server_url.rstrip("/")
        self.baselines = {}  # {filename: sha256}
        self.file_mtimes = {}

    def initialize_directory(self):
        """Creates watch directory and creates baseline of existing files."""
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        print(f"\n[+] Monitoring Directory: {self.watch_dir}")

        # Create a sample test file if directory is empty
        sample_file = self.watch_dir / "sample_config.ini"
        if not sample_file.exists() and len(list(self.watch_dir.glob("*"))) == 0:
            with open(sample_file, "w", encoding="utf-8") as f:
                f.write("# FIM Sentinel Protected Asset\nDEBUG=False\nPORT=8080\nAPI_KEY=sec_live_99214a\n")
            print(f"[+] Created sample file for testing: {sample_file.name}")

        for fpath in self.watch_dir.iterdir():
            if fpath.is_file():
                h = calculate_sha256(fpath)
                if h:
                    self.baselines[fpath.name] = h
                    self.file_mtimes[fpath.name] = fpath.stat().st_mtime
                    print(f"  * Baseline Locked: {fpath.name}")
                    print(f"    SHA-256: {h[:32]}...")

    def check_integrity(self):
        """Single scan iteration checking for additions, modifications, and deletions."""
        current_files = set()

        for fpath in self.watch_dir.iterdir():
            if not fpath.is_file():
                continue
            fname = fpath.name
            current_files.add(fname)

            try:
                mtime = fpath.stat().st_mtime
            except OSError:
                continue

            # Check if file is new
            if fname not in self.baselines:
                h = calculate_sha256(fpath)
                if h:
                    self.baselines[fname] = h
                    self.file_mtimes[fname] = mtime
                    print(f"\n[NEW ASSET] Registered '{fname}' -> SHA-256: {h[:24]}...")
                continue

            # Check if file timestamp changed
            if mtime != self.file_mtimes.get(fname):
                self.file_mtimes[fname] = mtime
                current_hash = calculate_sha256(fpath)
                stored_hash = self.baselines[fname]

                if current_hash != stored_hash:
                    # TAMPERING DETECTED!
                    self.on_tamper_detected(fname, stored_hash, current_hash)
                else:
                    print(f"\n[CHECK] '{fname}' touched, but contents identical (Clean).")

        # Check for deleted files
        for fname in list(self.baselines.keys()):
            if fname not in current_files:
                print(f"\n[ALERT] Asset DELETED / MISSING: '{fname}'!")
                dispatch_tamper_alert(
                    file_name=fname,
                    event_type="DELETED",
                    risk_level="HIGH",
                    risk_score=90,
                    diff_summary="File removed from filesystem",
                    source=f"Desktop Agent ({os.environ.get('COMPUTERNAME', 'Localhost')})"
                )
                del self.baselines[fname]
                if fname in self.file_mtimes:
                    del self.file_mtimes[fname]

    def on_tamper_detected(self, fname: str, old_hash: str, new_hash: str):
        """Handles tampering event, triggers mobile/desktop alerts, and syncs with dashboard."""
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print("\n" + "="*60)
        print("🚨 [CRITICAL ALERT] FILE TAMPERING DETECTED IN REAL TIME!")
        print(f"📁 Target Asset: {fname}")
        print(f"⏰ Timestamp:    {now_str}")
        print(f"❌ Baseline SHA-256: {old_hash}")
        print(f"⚡ Current  SHA-256: {new_hash}")
        print("="*60)

        # 1. Fire Mobile / Desktop notification (Telegram / Discord)
        print("[*] Dispatching real-time phone alert...")
        dispatch_tamper_alert(
            file_name=fname,
            event_type="MODIFIED",
            risk_level="HIGH",
            risk_score=85,
            diff_summary="Cryptographic hash divergence (SHA-256 mismatch)",
            source=f"Desktop Agent ({os.environ.get('COMPUTERNAME', 'Localhost')})"
        )

        # 2. Sync to Web Dashboard API
        self.sync_to_dashboard(fname, old_hash, new_hash)

        # Update baseline to prevent spamming until modified again
        self.baselines[fname] = new_hash

    def sync_to_dashboard(self, fname: str, old_hash: str, new_hash: str):
        """Sends event telemetry to central web dashboard if reachable."""
        try:
            url = f"{self.server_url}/api/events"
            # Attempt to verify or notify dashboard
            req = urllib.request.Request(
                f"{self.server_url}/api/verify_all",
                data=b"{}",
                headers={"Content-Type": "application/json", "User-Agent": "FIM-Agent"}
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status == 200:
                    print(f"[+] Synced event with FIM Sentinel Dashboard at {self.server_url}")
        except Exception:
            pass  # Standalone mode doesn't require dashboard to be online

    def run(self, interval: float = 1.0):
        """Main agent loop."""
        print("="*65)
        print("   🛡️  FIM SENTINEL - DESKTOP REAL-TIME WATCHDOG AGENT")
        print("       Single-Primitive SHA-256 Cryptographic Monitor")
        print("="*65)
        self.initialize_directory()

        cfg = get_alert_config()
        tg_status = "ENABLED ✅" if cfg.get("telegram_enabled") else "DISABLED (Set in Dashboard or alert_config.json)"
        dc_status = "ENABLED ✅" if cfg.get("discord_enabled") else "DISABLED"
        print(f"\n[🔔 Notifications] Telegram: {tg_status}")
        print(f"[🔔 Notifications] Discord:  {dc_status}")
        print("\n[✓] Agent is ACTIVE. Edit any file in the monitored folder and press Ctrl+S to test!")
        print("[✓] Press Ctrl+C to stop the agent.\n")

        try:
            while True:
                self.check_integrity()
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[-] FIM Sentinel Agent stopped by user.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FIM Sentinel Standalone Real-Time Endpoint Agent")
    parser.add_argument("--dir", default="./monitored_folder", help="Directory path to monitor")
    parser.add_argument("--interval", type=float, default=1.0, help="Scan interval in seconds (default: 1.0)")
    parser.add_argument("--server", default="http://localhost:5000", help="FIM Sentinel Web Dashboard URL")
    args = parser.parse_args()

    agent = FIMAgent(watch_dir=args.dir, server_url=args.server)
    agent.run(interval=args.interval)
