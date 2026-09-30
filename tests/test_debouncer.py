import unittest
import time
import tempfile
import queue
from pathlib import Path
from core.monitor import FileIntegrityMonitor
from database.db_manager import DBManager
from core.vault import SnapshotVault

import gc

class TestDebouncer(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = Path(self.temp_dir.name) / "debounce_test.sqlite3"
        self.vault_dir = Path(self.temp_dir.name) / ".debounce_vault"

        self.db = DBManager(self.db_path)
        self.vault = SnapshotVault(vault_dir=self.vault_dir, db=self.db)
        self.event_queue = queue.Queue()

        self.monitor = FileIntegrityMonitor(
            event_queue=self.event_queue,
            debounce_sec=0.20,
            db=self.db,
            vault=self.vault
        )

        # Create monitored target file
        self.target_file = Path(self.temp_dir.name) / "debounced_config.txt"
        self.target_file.write_text("initial baseline config", encoding="utf-8")

        from core.hasher import compute_dual_hash
        h = compute_dual_hash(self.target_file)
        self.file_id = self.db.add_monitored_file(
            file_path=str(self.target_file),
            file_name=self.target_file.name,
            sha256=h.sha256,
            sha3_256=h.sha3_256,
            file_size=h.file_size,
            last_modified=h.last_modified,
            is_binary=False
        )
        self.vault.store_snapshot(
            file_path=self.target_file,
            file_id=self.file_id,
            sha256=h.sha256,
            file_size=h.file_size
        )
        self.monitor.reload_monitored_files()

    def tearDown(self):
        self.monitor.stop()
        self.db.close()
        gc.collect()
        self.temp_dir.cleanup()


    def test_rapid_modifications_coalesced_into_single_alert(self):
        # Fire 4 rapid modified events within 50ms (simulating Windows atomic write / save)
        for i in range(4):
            self.target_file.write_text(f"rapid modification #{i}", encoding="utf-8")
            self.monitor.handle_raw_event("MODIFIED", str(self.target_file))
            time.sleep(0.01)

        # Wait for debounce interval (0.2s + buffer)
        time.sleep(0.35)

        # Confirm exactly 1 alert was posted to the event queue
        alerts = []
        while not self.event_queue.empty():
            alerts.append(self.event_queue.get())

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["type"], "TAMPER_ALERT")
        self.assertEqual(alert["file_name"], "debounced_config.txt")

if __name__ == "__main__":
    unittest.main()
