
"""Detect potential hardcoded secrets in text files."""

import os
import re
import stat
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
            r"""(?i)\b(?:[A-Z0-9]+[_-])?"""
            r"""(?:api[_-]?key|secret|secret[_-]?key|"""
            r"""access[_-]?token|auth[_-]?token|"""
            r"""client[_-]?secret|jwt[_-]?secret)"""
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
    (
        "POTENTIAL_PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        ),
    ),
    (
        "POTENTIAL_GITHUB_TOKEN",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,255}\b"),
    ),
]

ENVIRONMENT_REFERENCE = re.compile(
    r"""^(?:\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*)$"""
)


def scan_file(path: Path) -> ScanResult:
    """Scan one regular file and return findings and read errors."""
    findings: list[Finding] = []

    try:
        # Do not follow symlinks or attempt to read special files.
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
            return {
                "findings": [],
                "errors": [f"{path}: not a regular file"],
            }

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

    return {"findings": findings, "errors": []}


def _record_walk_error(exc: OSError, errors: list[str]) -> None:
    """Record directory traversal errors instead of silently ignoring them."""
    errors.append(f"{exc.filename or '<directory>'}: could not scan ({exc})")


def scan_directory(root: Path) -> ScanResult:
    """Scan regular files recursively and report traversal errors."""
    findings: list[Finding] = []
    errors: list[str] = []

    if root.is_symlink():
        return {
            "findings": [],
            "errors": [f"{root}: refusing to scan a symbolic link"],
        }

    if not root.is_dir():
        return {
            "findings": [],
            "errors": [f"{root}: not a directory"],
        }

    for current_root, directories, filenames in os.walk(
        root,
        topdown=True,
        followlinks=False,
        onerror=lambda exc: _record_walk_error(exc, errors),
    ):
        current_path = Path(current_root)

        # Do not traverse symbolic-link directories.
        directories[:] = sorted(
            name
            for name in directories
            if not (current_path / name).is_symlink()
        )

        for filename in sorted(filenames):
            path = current_path / filename

            # Avoid symbolic links and special files.
            if path.is_symlink():
                continue

            try:
                if not stat.S_ISREG(path.stat().st_mode):
                    continue
            except OSError as exc:
                errors.append(f"{path}: could not inspect file ({exc})")
                continue

            result = scan_file(path)
            findings.extend(result["findings"])
            errors.extend(result["errors"])

    return {"findings": findings, "errors": errors}
