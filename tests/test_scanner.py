
import tempfile
import unittest
from pathlib import Path

from configguard.scanner import scan_directory, scan_file

ROOT = Path(__file__).resolve().parent
VULNERABLE = ROOT / "fixtures" / "vulnerable"
SAFE = ROOT / "fixtures" / "safe"


class ScannerTests(unittest.TestCase):
    def test_detects_three_vulnerable_values(self):
        result = scan_directory(VULNERABLE)
        findings = result["findings"]

        self.assertEqual(len(findings), 3)
        self.assertEqual(result["errors"], [])

        rule_ids = {finding["rule_id"] for finding in findings}
        self.assertEqual(
            rule_ids,
            {
                "POTENTIAL_API_KEY",
                "POTENTIAL_AWS_ACCESS_KEY",
                "POTENTIAL_DATABASE_CREDENTIAL",
            },
        )

    def test_safe_fixture_has_no_findings(self):
        result = scan_directory(SAFE)

        self.assertEqual(result["findings"], [])
        self.assertEqual(result["errors"], [])

    def test_findings_include_line_numbers(self):
        findings = scan_directory(VULNERABLE)["findings"]

        for finding in findings:
            self.assertIsInstance(finding["line"], int)
            self.assertGreater(finding["line"], 0)

    def test_comments_are_ignored(self):
        findings = scan_file(VULNERABLE / "settings.env")["findings"]
        self.assertTrue(all(finding["line"] != 1 for finding in findings))

    def test_empty_file_has_no_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.env"
            path.write_text("", encoding="utf-8")

            result = scan_file(path)
            self.assertEqual(result["findings"], [])
            self.assertEqual(result["errors"], [])

    def test_environment_variable_reference_is_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "reference.env"
            path.write_text(
                "API_KEY=${API_KEY}\n"
                "ACCESS_TOKEN=$ACCESS_TOKEN\n",
                encoding="utf-8",
            )

            result = scan_file(path)
            self.assertEqual(result["findings"], [])
            self.assertEqual(result["errors"], [])

    def test_missing_file_returns_error(self):
        path = Path("/definitely-not-a-real-configguard-file.env")
        result = scan_file(path)

        self.assertEqual(result["findings"], [])
        self.assertEqual(len(result["errors"]), 1)


if __name__ == "__main__":
    unittest.main()
