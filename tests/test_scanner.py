import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from configguard.scanner import scan_directory, scan_file

ROOT = Path(__file__).resolve().parent
VULNERABLE = ROOT / "fixtures" / "vulnerable"
SAFE = ROOT / "fixtures" / "safe"
PROJECT_ROOT = ROOT.parent

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


class CLITests(unittest.TestCase):
    def run_cli(self, path: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "configguard.cli",
                str(path),
                "--json",
            ],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
        )

    def test_json_reports_vulnerable_fixture(self):
        result = self.run_cli(VULNERABLE)
        data = json.loads(result.stdout)

        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(data["findings"]), 3)
        self.assertEqual(data["errors"], [])

    def test_json_reports_safe_fixture(self):
        result = self.run_cli(SAFE)
        data = json.loads(result.stdout)

        self.assertEqual(result.returncode, 0)
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["errors"], [])

    def test_json_reports_missing_path(self):
        missing_path = PROJECT_ROOT / "does-not-exist.env"
        result = self.run_cli(missing_path)
        data = json.loads(result.stdout)

        self.assertEqual(result.returncode, 2)
        self.assertEqual(data["findings"], [])
        self.assertEqual(len(data["errors"]), 1)
    def test_symbolic_link_is_not_scanned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.env"
            link = root / "link.env"

            target.write_text(
                "API_KEY=sk-test-FAKE123456789012345678\n",
                encoding="utf-8",
            )

            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"Symbolic links unavailable: {exc}")

            result = scan_file(link)

            self.assertEqual(result["findings"], [])
            self.assertEqual(len(result["errors"]), 1)

    def test_directory_scan_skips_symbolic_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "scan"
            root.mkdir()

            outside = Path(directory) / "outside.env"
            link = root / "link.env"

            outside.write_text(
                "API_KEY=sk-test-FAKE123456789012345678\n",
                encoding="utf-8",
            )

            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"Symbolic links unavailable: {exc}")

            result = scan_directory(root)

            self.assertEqual(result["findings"], [])
            self.assertEqual(result["errors"], [])

if __name__ == "__main__":
    unittest.main()
