"""Scan statique Terraform — catch 0.0.0.0/0, S3 public, secrets en clair (shift-left)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


def check_terraform(directory: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not directory.exists():
        return findings
    for path in directory.rglob("*.tf"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        rel = str(path.as_posix())
        if re.search(r'cidr_blocks\s*=\s*\[?\s*"0\.0\.0\.0/0"', text):
            findings.append(
                {
                    "id": "CIS-5.2",
                    "title": "Terraform opens 0.0.0.0/0",
                    "severity": "HIGH",
                    "cis": "5.2 No world-open admin ports",
                    "resource": rel,
                    "remediation": "Restrict security group CIDRs before apply.",
                }
            )
        if "acl" in text.lower() and "public-read" in text.lower():
            findings.append(
                {
                    "id": "CIS-2.1.1",
                    "title": "Terraform S3 ACL public-read",
                    "severity": "CRITICAL",
                    "cis": "2.1.1 S3 not public",
                    "resource": rel,
                    "remediation": "Use private ACL + Block Public Access.",
                }
            )
        if re.search(r'password\s*=\s*"[^$]', text, re.I) and "var." not in text:
            findings.append(
                {
                    "id": "CIS-1.5",
                    "title": "Possible hardcoded secret in Terraform",
                    "severity": "CRITICAL",
                    "cis": "Secrets must not live in code",
                    "resource": rel,
                    "remediation": "Use variables marked sensitive + Vault/Secrets Manager.",
                }
            )
    return findings
