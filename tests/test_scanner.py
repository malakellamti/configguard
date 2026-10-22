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

    def test_detects_private_key_header(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-key.pem"
            path.write_text(
                "-----BEGIN RSA PRIVATE KEY-----\n"
                "FAKE-KEY-DATA\n"
                "-----END RSA PRIVATE KEY-----\n",
                encoding="utf-8",
            )

            result = scan_file(path)

            self.assertEqual(len(result["findings"]), 1)
            self.assertEqual(
                result["findings"][0]["rule_id"],
                "POTENTIAL_PRIVATE_KEY",
            )
            self.assertEqual(result["findings"][0]["line"], 1)

    def test_detects_github_style_token(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.env"
            path.write_text(
                "GITHUB_TOKEN=ghp_FAKE123456789012345678901234567890\n",
                encoding="utf-8",
            )

            result = scan_file(path)

            self.assertEqual(len(result["findings"]), 1)
            self.assertEqual(
                result["findings"][0]["rule_id"],
                "POTENTIAL_GITHUB_TOKEN",
            )
            self.assertEqual(result["findings"][0]["line"], 1)

    def test_detects_common_secret_variable_names(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secrets.env"
            path.write_text(
                "STRIPE_SECRET=sk_live_FAKE123456789\n"
                "JWT_SECRET=my-fake-secret-value\n"
                "CLIENT_SECRET=fake-client-secret\n"
                "AUTH_TOKEN=fake-auth-token\n",
                encoding="utf-8",
            )

            result = scan_file(path)

            self.assertEqual(len(result["findings"]), 4)
            self.assertEqual(result["errors"], [])
            self.assertTrue(
                all(
                    finding["rule_id"] == "POTENTIAL_API_KEY"
                    for finding in result["findings"]
                )
            )
            self.assertEqual(
                [finding["line"] for finding in result["findings"]],
                [1, 2, 3, 4],
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

    def test_github_environment_variable_reference_is_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "reference.env"
            path.write_text(
                "GITHUB_TOKEN=${GITHUB_TOKEN}\n"
                "GITHUB_TOKEN=$GITHUB_TOKEN\n",
                encoding="utf-8",
            )

            result = scan_file(path)

            self.assertEqual(result["findings"], [])
            self.assertEqual(result["errors"], [])

    def test_github_token_in_comment_is_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "comments.env"
            path.write_text(
                "# GITHUB_TOKEN=ghp_FAKE123456789012345678901234567890\n",
                encoding="utf-8",
            )

            result = scan_file(path)

            self.assertEqual(result["findings"], [])
            self.assertEqual(result["errors"], [])

    def test_short_github_like_string_is_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "short.env"
            path.write_text(
                "GITHUB_TOKEN=ghp_not-a-real-token\n",
                encoding="utf-8",
            )

            result = scan_file(path)

            self.assertEqual(result["findings"], [])
            self.assertEqual(result["errors"], [])


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
