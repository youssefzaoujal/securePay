"""CIS 2.1 — S3 public access."""

from __future__ import annotations

from typing import Any


def check_s3(buckets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for bucket in buckets:
        if bucket.get("public"):
            findings.append(
                {
                    "id": "CIS-2.1.1",
                    "title": "S3 bucket publicly accessible",
                    "severity": "CRITICAL",
                    "cis": "2.1.1 Ensure S3 Bucket Policy does not allow public access",
                    "resource": f"s3://{bucket.get('name')}",
                    "remediation": "Enable Block Public Access and tighten bucket policy.",
                }
            )
        if bucket.get("encryption") is False:
            findings.append(
                {
                    "id": "CIS-2.1.4",
                    "title": "S3 bucket without default encryption",
                    "severity": "HIGH",
                    "cis": "2.1.4 Ensure S3 default encryption is enabled",
                    "resource": f"s3://{bucket.get('name')}",
                    "remediation": "Set AES256 or aws:kms default encryption.",
                }
            )
    return findings
