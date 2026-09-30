import unittest
import tempfile
import hashlib
from pathlib import Path
from core.hasher import compute_dual_hash, is_binary_buffer

class TestHasher(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file = Path(self.temp_dir.name) / "test_sample.txt"
        self.sample_bytes = b"Security file integrity test.\nLine 2 with configuration."
        self.test_file.write_bytes(self.sample_bytes)


    def tearDown(self):
        self.temp_dir.cleanup()

    def test_single_pass_dual_hash_accuracy(self):
        result = compute_dual_hash(self.test_file)

        # Independently compute standard SHA-256 and SHA-3-256
        b_data = self.sample_bytes
        expected_sha256 = hashlib.sha256(b_data).hexdigest()
        expected_sha3 = hashlib.sha3_256(b_data).hexdigest()


        self.assertIsNone(result.error)
        self.assertEqual(result.sha256, expected_sha256)
        self.assertEqual(result.sha3_256, expected_sha3)
        self.assertEqual(result.file_size, len(b_data))
        self.assertFalse(result.is_binary)

    def test_binary_buffer_detection(self):
        text_buf = b"This is plain ASCII and UTF-8 text with newlines.\n"
        binary_buf = b"GIF89a\x00\x00\x01\x00\x80\x00\x00"

        self.assertFalse(is_binary_buffer(text_buf))
        self.assertTrue(is_binary_buffer(binary_buf))

    def test_missing_file_handling(self):
        fake_path = Path(self.temp_dir.name) / "non_existent.txt"
        res = compute_dual_hash(fake_path)
        self.assertIsNotNone(res.error)
        self.assertEqual(res.sha256, "")

if __name__ == "__main__":
    unittest.main()
