import subprocess
import unittest


class GeneratedEvidenceHygieneTest(unittest.TestCase):
    def test_checker_accepts_current_tree(self):
        output = subprocess.check_output(
            ["python", "scripts/check_generated_evidence_hygiene.py"],
            text=True,
        )
        self.assertIn("generated evidence hygiene: ok", output)
