"""CIS 1.x — IAM."""

from __future__ import annotations

from typing import Any


def check_iam(iam: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    if iam.get("root_access_keys"):
        findings.append(
            {
                "id": "CIS-1.4",
                "title": "Root account has access keys",
                "severity": "CRITICAL",
                "cis": "1.4 Ensure no access keys exist for root",
                "resource": "account/root",
                "remediation": "Delete root access keys; use IAM roles + MFA.",
            }
        )
    for user in iam.get("admin_users") or []:
        findings.append(
            {
                "id": "CIS-1.16",
                "title": "IAM user with AdministratorAccess",
                "severity": "HIGH",
                "cis": "1.16 Ensure IAM policies that allow full admin are not attached to users",
                "resource": f"iam:user/{user}",
                "remediation": "Attach admin via role assumed with MFA, not directly on a user.",
            }
        )
    wildcard = iam.get("wildcard_policies") or []
    for policy in wildcard:
        findings.append(
            {
                "id": "CIS-1.16",
                "title": "Over-permissive IAM policy Action=* Resource=*",
                "severity": "HIGH",
                "cis": "1.16 Least privilege",
                "resource": policy,
                "remediation": "Scope actions and resources; deny *:* on humans.",
            }
        )
    return findings
