import unittest
import io
import os
import tempfile
from pathlib import Path

import config
import database.db_manager
import core.vault
from database.db_manager import DBManager
from core.vault import SnapshotVault
import web_app


class TestWebAPI(unittest.TestCase):
    """
    Automated Web API test suite for FIM Sentinel serverless/web backend.
    Tests baseline establishment, integrity verification, tampering detection,
    duplicate alert suppression, binary diff handling, forensic reports,
    and demo mode lifecycle.
    """

    def setUp(self):
        # Create isolated temporary directory for test DB and vault
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_api_fim.sqlite3"
        self.test_vault_dir = Path(self.temp_dir.name) / ".test_api_vault"

        # Instantiate isolated test DB and vault
        self.test_db = DBManager(self.test_db_path)
        self.test_vault = SnapshotVault(
            vault_dir=self.test_vault_dir,
            max_size_bytes=1024 * 1024,
            db=self.test_db
        )

        # Save original singletons & references
        self._orig_db_class_instance = DBManager._instance
        self._orig_get_db = database.db_manager.get_db
        self._orig_get_vault = core.vault.get_vault
        self._orig_webapp_db = web_app.db
        self._orig_webapp_vault = web_app.vault

        # Inject test instances into modules
        DBManager._instance = self.test_db
        database.db_manager.get_db = lambda *args, **kwargs: self.test_db
        core.vault.get_vault = lambda *args, **kwargs: self.test_vault
        web_app.db = self.test_db
        web_app.vault = self.test_vault

        # Configure Flask test client
        web_app.app.config["TESTING"] = True
        self.client = web_app.app.test_client()

    def tearDown(self):
        # Close test DB
        self.test_db.close()

        # Restore original singletons & references
        DBManager._instance = self._orig_db_class_instance
        database.db_manager.get_db = self._orig_get_db
        core.vault.get_vault = self._orig_get_vault
        web_app.db = self._orig_webapp_db
        web_app.vault = self._orig_webapp_vault

        # Clean up temporary storage
        self.temp_dir.cleanup()

    def test_baseline_creation(self):
        """
        POST /api/upload_baseline should dual-hash the uploaded file,
        store it in database & vault, and return UNCHANGED status.
        """
        payload = b"ENABLE_FIREWALL = True\nALLOWED_PORTS = [80, 443]\n"
        data = {
            "file": (io.BytesIO(payload), "firewall_config.py")
        }
        res = self.client.post("/api/upload_baseline", data=data, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 200)

        json_data = res.get_json()
        self.assertTrue(json_data["success"])
        self.assertIn("file_id", json_data)
        self.assertEqual(json_data["file_name"], "firewall_config.py")
        self.assertEqual(len(json_data["sha256"]), 64)
        self.assertEqual(len(json_data["sha3_256"]), 64)
        self.assertEqual(json_data["status"], config.STATUS_UNCHANGED)
        self.assertFalse(json_data["re_baselined"])

        # Verify vault snapshot exists
        snapshot_text = self.test_vault.read_snapshot_text(json_data["file_id"])
        self.assertIn("ALLOWED_PORTS = [80, 443]", snapshot_text)

    def test_unchanged_verification(self):
        """
        POST /api/upload_verify with identical file content should return UNCHANGED
        and NOT create any modification alerts in event history.
        """
        payload = b"ENABLE_FIREWALL = True\nALLOWED_PORTS = [80, 443]\n"
        # 1. Establish baseline
        self.client.post(
            "/api/upload_baseline",
            data={"file": (io.BytesIO(payload), "firewall_config.py")},
            content_type="multipart/form-data"
        )

        # 2. Verify with unchanged content
        res = self.client.post(
            "/api/upload_verify",
            data={"file": (io.BytesIO(payload), "firewall_config.py")},
            content_type="multipart/form-data"
        )
        self.assertEqual(res.status_code, 200)

        json_data = res.get_json()
        self.assertEqual(json_data["status"], config.STATUS_UNCHANGED)
        self.assertEqual(json_data["risk_level"], "LOW")
        self.assertEqual(json_data["risk_score"], 0)
        self.assertFalse(json_data["duplicate_alert_suppressed"])

        # 3. Verify event history is empty (no false alarm logged)
        events_res = self.client.get("/api/events")
        self.assertEqual(events_res.status_code, 200)
        events = events_res.get_json()
        self.assertEqual(len(events), 0)

    def test_modified_detection(self):
        """
        POST /api/upload_verify with altered file content should detect tampering,
        compute diff and risk score, and log an audit event.
        """
        baseline_payload = b"ENABLE_FIREWALL = True\nALLOWED_PORTS = [80, 443]\n"
        tampered_payload = b"ENABLE_FIREWALL = False\nALLOWED_PORTS = [0, 65535]\n"

        # 1. Baseline
        base_res = self.client.post(
            "/api/upload_baseline",
            data={"file": (io.BytesIO(baseline_payload), "firewall_config.py")},
            content_type="multipart/form-data"
        )
        file_id = base_res.get_json()["file_id"]

        # 2. Verify with modified payload
        verify_res = self.client.post(
            "/api/upload_verify",
            data={"file": (io.BytesIO(tampered_payload), "firewall_config.py")},
            content_type="multipart/form-data"
        )
        self.assertEqual(verify_res.status_code, 200)

        data = verify_res.get_json()
        self.assertEqual(data["status"], config.STATUS_MODIFIED)
        self.assertEqual(data["file_id"], file_id)
        self.assertIn("event_id", data)
        self.assertGreater(data["risk_score"], 0)
        self.assertIn("raw_diff", data)
        self.assertIn("-ENABLE_FIREWALL = True", data["raw_diff"])
        self.assertIn("+ENABLE_FIREWALL = False", data["raw_diff"])
        self.assertFalse(data["duplicate_alert_suppressed"])

        # 3. Check event history has exactly 1 event
        events_res = self.client.get("/api/events")
        events = events_res.get_json()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["id"], data["event_id"])
        self.assertEqual(events[0]["event_type"], config.STATUS_MODIFIED)

    def test_duplicate_alert_prevention(self):
        """
        Repeatedly verifying the SAME modified content must suppress duplicate alerts
        and not spam the audit event log.
        """
        baseline_payload = b"AUTH_REQUIRED = True\n"
        tampered_payload = b"AUTH_REQUIRED = False\n"

        # 1. Baseline
        self.client.post(
            "/api/upload_baseline",
            data={"file": (io.BytesIO(baseline_payload), "auth_gate.py")},
            content_type="multipart/form-data"
        )

        # 2. First tamper verification (creates event)
        res1 = self.client.post(
            "/api/upload_verify",
            data={"file": (io.BytesIO(tampered_payload), "auth_gate.py")},
            content_type="multipart/form-data"
        )
        data1 = res1.get_json()
        self.assertEqual(data1["status"], config.STATUS_MODIFIED)
        self.assertFalse(data1["duplicate_alert_suppressed"])
        first_event_id = data1["event_id"]

        # 3. Second tamper verification with identical modified content
        res2 = self.client.post(
            "/api/upload_verify",
            data={"file": (io.BytesIO(tampered_payload), "auth_gate.py")},
            content_type="multipart/form-data"
        )
        data2 = res2.get_json()
        self.assertEqual(data2["status"], config.STATUS_MODIFIED)
        self.assertTrue(data2["duplicate_alert_suppressed"])
        self.assertEqual(data2["event_id"], first_event_id)

        # 4. Confirm total events count remains 1
        events = self.client.get("/api/events").get_json()
        self.assertEqual(len(events), 1)

    def test_binary_file_diff(self):
        """
        Binary files must show structured metadata size delta and suppress
        raw text diffing to avoid display corruption.
        """
        baseline_bytes = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        tampered_bytes = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x90\x90\x90"

        # 1. Baseline binary
        self.client.post(
            "/api/upload_baseline",
            data={"file": (io.BytesIO(baseline_bytes), "kernel_driver.sys")},
            content_type="multipart/form-data"
        )

        # 2. Verify modified binary
        res = self.client.post(
            "/api/upload_verify",
            data={"file": (io.BytesIO(tampered_bytes), "kernel_driver.sys")},
            content_type="multipart/form-data"
        )
        self.assertEqual(res.status_code, 200)

        data = res.get_json()
        self.assertEqual(data["status"], config.STATUS_MODIFIED)
        self.assertTrue(data["is_binary"])
        self.assertIn("Binary size delta: +3 bytes", data["diff_summary"])
        self.assertIn("Binary File Detected: Raw text diff suppressed", data["raw_diff"])

    def test_report_download(self):
        """
        GET /api/download_report/<event_id> must return an HTML attachment
        with correct headers and forensic audit sections.
        """
        baseline_payload = b"ROLE = 'user'\n"
        tampered_payload = b"ROLE = 'admin'\n"

        self.client.post(
            "/api/upload_baseline",
            data={"file": (io.BytesIO(baseline_payload), "role_def.py")},
            content_type="multipart/form-data"
        )

        verify_res = self.client.post(
            "/api/upload_verify",
            data={"file": (io.BytesIO(tampered_payload), "role_def.py")},
            content_type="multipart/form-data"
        )
        event_id = verify_res.get_json()["event_id"]

        # Download report
        dl_res = self.client.get(f"/api/download_report/{event_id}")
        self.assertEqual(dl_res.status_code, 200)
        self.assertIn("text/html", dl_res.content_type)
        self.assertIn("attachment; filename=", dl_res.headers.get("Content-Disposition", ""))

        html_body = dl_res.get_data(as_text=True)
        self.assertIn("FIM Forensic Audit Report", html_body)
        self.assertIn("role_def.py", html_body)
        self.assertIn("Deterministic Heuristic Risk Analysis", html_body)
        self.assertIn("Unified Syntactic Diff Delta", html_body)

        # Inline view report
        view_res = self.client.get(f"/api/view_report/{event_id}")
        self.assertEqual(view_res.status_code, 200)
        self.assertIn("text/html", view_res.content_type)

    def test_demo_mode_workflow(self):
        """
        Demo mode must seed attack scenarios and clear only demo-tagged records,
        preserving real user baselines.
        """
        # 1. Add a real baseline
        self.client.post(
            "/api/upload_baseline",
            data={"file": (io.BytesIO(b"REAL_DATA = 123\n"), "real_production.py")},
            content_type="multipart/form-data"
        )

        # 2. Seed demo
        seed_res = self.client.post("/api/demo/seed")
        self.assertEqual(seed_res.status_code, 200)
        seed_data = seed_res.get_json()
        self.assertTrue(seed_data["success"])
        self.assertEqual(len(seed_data["seeded"]), 3)

        # 3. Verify demo files appear
        files_res = self.client.get("/api/files?include_demo=true")
        files = files_res.get_json()
        file_names = [f["file_name"] for f in files]
        self.assertIn("auth_policy.py", file_names)
        self.assertIn("server_config.ini", file_names)
        self.assertIn("system_manifest.json", file_names)
        self.assertIn("real_production.py", file_names)

        # 4. Clear demo files
        clear_res = self.client.post("/api/demo/clear")
        self.assertEqual(clear_res.status_code, 200)
        self.assertTrue(clear_res.get_json()["success"])

        # 5. Verify real baseline persists, demo files removed
        files_after = self.client.get("/api/files?include_demo=true").get_json()
        names_after = [f["file_name"] for f in files_after]
        self.assertIn("real_production.py", names_after)
        self.assertNotIn("auth_policy.py", names_after)

    def test_empty_file_upload_validation(self):
        """
        Uploading an empty (0 byte) file must return a 400 Bad Request.
        """
        res = self.client.post(
            "/api/upload_baseline",
            data={"file": (io.BytesIO(b""), "empty.txt")},
            content_type="multipart/form-data"
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("empty", res.get_json()["error"].lower())

    def test_agent_info_architecture_endpoint(self):
        """
        GET /api/agent_info must clearly distinguish cloud verification from local agent.
        """
        res = self.client.get("/api/agent_info")
        self.assertEqual(res.status_code, 200)
        info = res.get_json()
        self.assertIn("cloud_capabilities", info)
        self.assertIn("local_agent_capabilities", info)
        self.assertIn("notice", info)
        self.assertIn("browser security sandboxes", info["notice"].lower())


if __name__ == "__main__":
    unittest.main()
