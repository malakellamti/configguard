
"""Detect potential hardcoded secrets in text files."""

import re
from pathlib import Path
from typing import TypedDict


class Finding(TypedDict):
    rule_id: str
    file: str
    line: int
    message: str


class ScanResult(TypedDict):
    findings: list[Finding]
    errors: list[str]


SECRET_PATTERNS = [
    (
        "POTENTIAL_API_KEY",
        re.compile(
            r"""(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)"""
            r"""\s*[:=]\s*["']?([A-Za-z0-9_\-./+=${}]{1,})"""
        ),
    ),
    (
        "POTENTIAL_AWS_ACCESS_KEY",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "POTENTIAL_DATABASE_CREDENTIAL",
        re.compile(
            r"""(?i)\b(?:postgres|mysql|mongodb)://[^:\s/]+:"""
            r"""[^@\s/]+@"""
        ),
    ),
]

ENVIRONMENT_REFERENCE = re.compile(
    r"""^(?:\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*)$"""
)


def scan_file(path: Path) -> ScanResult:
    """Scan one file and return findings and any read errors."""
    findings: list[Finding] = []
    errors: list[str] = []

    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return {
            "findings": [],
            "errors": [f"{path}: could not read file ({exc})"],
        }

    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        for rule_id, pattern in SECRET_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue

            value = match.group(1) if match.lastindex else match.group(0)

            if ENVIRONMENT_REFERENCE.fullmatch(value):
                continue

            findings.append(
                {
                    "rule_id": rule_id,
                    "file": str(path),
                    "line": line_number,
                    "message": "Potential hardcoded secret detected.",
                }
            )

    return {"findings": findings, "errors": errors}


def scan_directory(root: Path) -> ScanResult:
    """Scan files recursively without executing them."""
    findings: list[Finding] = []
    errors: list[str] = []

    try:
        paths = sorted(root.rglob("*"))
        for path in paths:
            if path.is_file():
                result = scan_file(path)
                findings.extend(result["findings"])
                errors.extend(result["errors"])
    except OSError as exc:
        errors.append(f"{root}: could not scan directory ({exc})")

    return {"findings": findings, "errors": errors}
