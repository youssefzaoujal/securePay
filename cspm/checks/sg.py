"""CIS 5.2 — Security groups 0.0.0.0/0."""

from __future__ import annotations

from typing import Any

SENSITIVE_PORTS = {22, 3389, 3306, 5432, 6379, 27017, 9200}


def check_security_groups(groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for sg in groups:
        for rule in sg.get("ingress") or []:
            cidrs = []
            if "CidrIp" in rule:
                cidrs.append(rule["CidrIp"])
            for ip_range in rule.get("IpRanges") or []:
                cidrs.append(ip_range.get("CidrIp"))
            from_port = rule.get("FromPort") or rule.get("from_port")
            if "0.0.0.0/0" not in cidrs:
                continue
            port = int(from_port) if from_port is not None else 0
            if port in SENSITIVE_PORTS or from_port is None:
                findings.append(
                    {
                        "id": "CIS-5.2",
                        "title": f"Security group open to the world on port {from_port or 'ALL'}",
                        "severity": "CRITICAL" if port in {22, 3389, 5432} else "HIGH",
                        "cis": "5.2 Ensure no security groups allow ingress from 0.0.0.0/0 to remote admin ports",
                        "resource": sg.get("id") or sg.get("name"),
                        "remediation": "Restrict CIDR to office/VPN; prefer SSM Session Manager over SSH.",
                    }
                )
    return findings
