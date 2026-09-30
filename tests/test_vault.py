import unittest
import tempfile
from pathlib import Path
from core.vault import SnapshotVault
from database.db_manager import DBManager
from core.hasher import compute_dual_hash

class TestVault(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_fim.sqlite3"
        self.vault_dir = Path(self.temp_dir.name) / ".test_vault"

        self.db = DBManager(self.db_path)
        self.vault = SnapshotVault(vault_dir=self.vault_dir, max_size_bytes=1024 * 1024, db=self.db)


        self.sample_file = Path(self.temp_dir.name) / "config.ini"
        self.sample_file.write_text("[database]\nhost=localhost\nport=5432\n", encoding="utf-8")

    def tearDown(self):
        self.db.close()
        self.temp_dir.cleanup()


    def test_store_and_retrieve_snapshot(self):
        h_res = compute_dual_hash(self.sample_file)
        file_id = self.db.add_monitored_file(
            file_path=str(self.sample_file),
            file_name="config.ini",
            sha256=h_res.sha256,
            sha3_256=h_res.sha3_256,
            file_size=h_res.file_size,
            last_modified=h_res.last_modified,
            is_binary=False
        )

        vault_path = self.vault.store_snapshot(
            file_path=self.sample_file,
            file_id=file_id,
            sha256=h_res.sha256,
            file_size=h_res.file_size,
            is_binary=False
        )
        self.assertIsNotNone(vault_path)
        self.assertTrue(Path(vault_path).exists())

        # Retrieve content from vault
        content = self.vault.read_snapshot_text(file_id)
        self.assertIn("port=5432", content)

    def test_purge_snapshot(self):
        h_res = compute_dual_hash(self.sample_file)
        file_id = self.db.add_monitored_file(
            file_path=str(self.sample_file),
            file_name="config.ini",
            sha256=h_res.sha256,
            sha3_256=h_res.sha3_256,
            file_size=h_res.file_size,
            last_modified=h_res.last_modified,
            is_binary=False
        )
        vault_path = self.vault.store_snapshot(
            file_path=self.sample_file,
            file_id=file_id,
            sha256=h_res.sha256,
            file_size=h_res.file_size
        )
        self.assertTrue(Path(vault_path).exists())

        self.vault.purge_snapshot(file_id)
        self.assertFalse(Path(vault_path).exists())

if __name__ == "__main__":
    unittest.main()
