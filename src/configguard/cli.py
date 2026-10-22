
"""Command-line interface for ConfigGuard."""

import argparse
import sys
from pathlib import Path

from configguard.scanner import scan_directory, scan_file


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="configguard",
        description="Scan files for potential hardcoded secrets.",
    )
    parser.add_argument("path", type=Path, help="File or directory to scan")
    args = parser.parse_args()

    target = args.path.expanduser()

    if not target.exists():
        print(f"Error: path does not exist: {target}", file=sys.stderr)
        return 2

    if target.is_file():
        result = scan_file(target)
    elif target.is_dir():
        result = scan_directory(target)
    else:
        print(
            f"Error: not a regular file or directory: {target}",
            file=sys.stderr,
        )
        return 2

    findings = result["findings"]
    errors = result["errors"]

    print(f"ConfigGuard scan: {target}")
    print(f"Findings: {len(findings)}")
    print(f"Scan errors: {len(errors)}")

    for finding in findings:
        print(
            f"[{finding['rule_id']}] "
            f"{finding['file']}:{finding['line']} - "
            f"{finding['message']}"
        )

    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)

    if errors:
        print("Scan incomplete; do not treat this result as clean.")
        return 2

    if findings:
        print("\nReview these matches manually; they may be false positives.")
        return 1

    print("No potential hardcoded secrets detected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
