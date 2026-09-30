import unittest
from core.comparator import ComparisonResult, DiffLine
from core.risk_analyzer import analyze_diff_risk

class TestRiskAnalyzer(unittest.TestCase):
    def test_high_risk_privilege_escalation(self):
        diff_lines = [
            DiffLine(line_type="+", line_no_old=None, line_no_new=1, content="chmod 777 /var/www/config.php"),
            DiffLine(line_type="+", line_no_old=None, line_no_new=2, content="admin = true")
        ]
        comp = ComparisonResult(
            is_binary=False,
            is_identical=False,
            diff_lines=diff_lines,
            added_count=2,
            deleted_count=0
        )

        risk = analyze_diff_risk(comp, file_path="config.php")
        self.assertEqual(risk.risk_level, "HIGH")
        self.assertGreaterEqual(risk.overall_score, 35)
        rule_ids = [r.rule_id for r in risk.triggered_rules]
        self.assertIn("HIGH_PRIV_ESC", rule_ids)

    def test_high_risk_defense_evasion(self):
        diff_lines = [
            DiffLine(line_type="+", line_no_old=None, line_no_new=1, content="Set-MpPreference -DisableRealtimeMonitoring $true"),
            DiffLine(line_type="+", line_no_old=None, line_no_new=2, content="netsh advfirewall set allprofiles state off")
        ]
        comp = ComparisonResult(
            is_binary=False,
            is_identical=False,
            diff_lines=diff_lines,
            added_count=2,
            deleted_count=0
        )

        risk = analyze_diff_risk(comp, file_path="script.ps1")
        self.assertEqual(risk.risk_level, "HIGH")
        rule_ids = [r.rule_id for r in risk.triggered_rules]
        self.assertIn("HIGH_FIREWALL_DISABLE", rule_ids)

    def test_low_risk_cosmetic(self):
        diff_lines = [
            DiffLine(line_type="+", line_no_old=None, line_no_new=1, content="timeout = 30"),
            DiffLine(line_type="+", line_no_old=None, line_no_new=2, content="retries = 3")
        ]
        comp = ComparisonResult(
            is_binary=False,
            is_identical=False,
            diff_lines=diff_lines,
            added_count=2,
            deleted_count=0
        )

        risk = analyze_diff_risk(comp, file_path="settings.conf")
        self.assertEqual(risk.risk_level, "LOW")
        self.assertLess(risk.overall_score, 20)

if __name__ == "__main__":
    unittest.main()
