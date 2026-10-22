
"""Command-line interface for ConfigGuard."""

import argparse
import json
import sys
from pathlib import Path

from configguard.scanner import scan_directory, scan_file


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="configguard",
        description="Scan files for potential hardcoded secrets.",
    )
    parser.add_argument("path", type=Path, help="File or directory to scan")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    args = parser.parse_args()

    target = args.path.expanduser()

    if not target.exists():
        error = f"Path does not exist: {target}"
        if args.json:
            print(json.dumps({
                "target": str(target),
                "findings": [],
                "errors": [error],
            }, indent=2))
        else:
            print(f"Error: {error}", file=sys.stderr)
        return 2

    if target.is_file():
        result = scan_file(target)
    elif target.is_dir():
        result = scan_directory(target)
    else:
        error = f"Not a regular file or directory: {target}"
        if args.json:
            print(json.dumps({
                "target": str(target),
                "findings": [],
                "errors": [error],
            }, indent=2))
        else:
            print(f"Error: {error}", file=sys.stderr)
        return 2

    findings = result["findings"]
    errors = result["errors"]

    if args.json:
        print(json.dumps({
            "target": str(target),
            "findings": findings,
            "errors": errors,
        }, indent=2))
    else:
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
        elif findings:
            print(
                "\nReview these matches manually; "
                "they may be false positives."
            )
        else:
            print("No potential hardcoded secrets detected.")

    if errors:
        return 2
    if findings:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
