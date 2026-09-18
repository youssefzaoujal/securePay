"""CIS 2.2.1 EBS encryption + 3.1 CloudTrail."""

from __future__ import annotations

from typing import Any


def check_ebs_and_trail(volumes: list[dict[str, Any]], cloudtrail: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    for vol in volumes:
        if not vol.get("encrypted"):
            findings.append(
                {
                    "id": "CIS-2.2.1",
                    "title": "EBS volume not encrypted",
                    "severity": "HIGH",
                    "cis": "2.2.1 Ensure EBS volume encryption is enabled",
                    "resource": vol.get("id"),
                    "remediation": "Enable encryption by default in the account/region.",
                }
            )
    if not cloudtrail.get("enabled"):
        findings.append(
            {
                "id": "CIS-3.1",
                "title": "CloudTrail is not enabled",
                "severity": "CRITICAL",
                "cis": "3.1 Ensure CloudTrail is enabled in all regions",
                "resource": "cloudtrail",
                "remediation": "Create a multi-region trail with log file validation.",
            }
        )
    return findings
