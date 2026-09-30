import unittest
from core.ai_advisor import sanitize_diff_content

class TestSanitizer(unittest.TestCase):
    def test_redaction_of_api_keys_and_passwords(self):
        raw_diff = (
            '+ api_key = "AIzaSyD59483948574839485738495839485"\n'
            '+ db_password = "SuperSecretPassword123!"\n'
            '+ auth_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"\n'
            '+ server_ip = "192.168.1.100"\n'
        )
        sanitized = sanitize_diff_content(raw_diff)

        self.assertNotIn("SuperSecretPassword123!", sanitized)
        self.assertNotIn("AIzaSyD59483948574839485738495839485", sanitized)
        self.assertNotIn("192.168.1.100", sanitized)
        self.assertIn("[REDACTED_SECRET]", sanitized)
        self.assertIn("[REDACTED_IP_ADDR]", sanitized)

    def test_line_truncation(self):
        # Generate 200 lines
        many_lines = "\n".join([f"+ line number {i}" for i in range(200)])
        sanitized = sanitize_diff_content(many_lines, max_lines=50)

        lines = sanitized.splitlines()
        # Should contain truncation notice and no more than max_lines of actual content
        self.assertIn("[... Diff truncated:", sanitized)
        self.assertLessEqual(len([l for l in lines if l.startswith("+ line number")]), 50)

if __name__ == "__main__":
    unittest.main()
