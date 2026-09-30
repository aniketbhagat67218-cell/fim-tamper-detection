import unittest
from core.comparator import generate_line_diff

class TestComparator(unittest.TestCase):
    def test_line_diff_additions_deletions(self):
        baseline = ["line1", "line2", "line3"]
        current = ["line1", "line2_modified", "line3", "line4_added"]

        diff_lines, added_count, deleted_count = generate_line_diff(baseline, current)

        self.assertGreater(added_count, 0)
        self.assertGreater(deleted_count, 0)

        # Check line tags
        types = [d.line_type for d in diff_lines]
        self.assertIn("+", types)
        self.assertIn("-", types)
        self.assertIn(" ", types)

    def test_identical_lines(self):
        baseline = ["alpha", "beta", "gamma"]
        current = ["alpha", "beta", "gamma"]

        diff_lines, added_count, deleted_count = generate_line_diff(baseline, current)
        self.assertEqual(added_count, 0)
        self.assertEqual(deleted_count, 0)
        self.assertTrue(all(d.line_type == " " for d in diff_lines))

if __name__ == "__main__":
    unittest.main()
