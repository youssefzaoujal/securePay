"""Audit PCI-DSS inspiré — vérifie la *présence* des contrôles dans le repo (lab)."""

from __future__ import annotations

import json
from pathlib import Path

CHECKS = [
    ("Req 3.2", "CVV jamais stocké", Path("tokenization/crypto.py"), "cvv"),
    ("Req 3.4", "AES-256-GCM", Path("tokenization/crypto.py"), "AES-256-GCM"),
    ("Req 4", "TLS 1.3", Path("infra/nginx/nginx.conf"), "TLSv1.3"),
    ("Req 6", "SAST Semgrep", Path(".github/workflows/ci.yml"), "Semgrep"),
    ("Req 6", "Trivy gate", Path(".github/workflows/ci.yml"), "Trivy"),
    ("Req 6", "SBOM CycloneDX", Path(".github/workflows/ci.yml"), "cyclonedx"),
    ("Req 7", "BOLA object-level", Path("shared/bola.py"), "assert_object_owner"),
    ("Req 8", "OAuth2 JWKS", Path("shared/auth.py"), "JWKS"),
    ("Req 10", "JSON logs redact", Path("shared/redaction.py"), "mask_pan"),
    ("Req 11", "Falco", Path("k8s-security/falco/rules.yml"), "Shell Spawned"),
    ("Req 12", "Runbooks IR", Path("detection/ir/runbook_card_testing.md"), "Containment"),
    ("Supply chain", "Cosign Kyverno", Path("k8s-security/kyverno/verify-cosign.yml"), "verifyImages"),
    ("Supply chain", "SLSA provenance", Path(".github/workflows/slsa.yml"), "slsa-github-generator"),
    ("SOC", "TheHive connector", Path("detection/hive/case_manager.py"), "open_case"),
    ("Legacy", "GnuCOBOL core", Path("legacy_core/cobol/VALIDATE.cob"), "VALIDATE-ACCOUNT"),
    ("Legacy", "mTLS adapter", Path("legacy_core/wrapper.py"), "Rate limit"),
    ("Req 6", "SARIF GitHub", Path(".github/workflows/ci.yml"), "upload-sarif"),
    ("Req 6", "Idempotence capture", Path("payment/idempotency.py"), "Idempotency-Key"),
    ("Ledger", "Partie double", Path("payment/ledger.py"), "scheme_receivable"),
    ("ATM", "ISO 8583 0200/0210", Path("atm/iso8583.py"), "0210"),
    ("ATM", "Recettes KaNest LSB", Path("atm/kanest/scenarios.yaml"), "ATM-LSB-001"),
]


def run_audit() -> dict:
    results = []
    for req, title, path, needle in CHECKS:
        ok = path.exists() and needle.lower() in path.read_text(encoding="utf-8", errors="ignore").lower()
        results.append({"req": req, "title": title, "file": str(path), "pass": ok})
    passed = sum(1 for r in results if r["pass"])
    return {
        "disclaimer": "Simulation — pas une certification PCI-DSS",
        "passed": passed,
        "total": len(results),
        "score_pct": round(100 * passed / len(results), 1),
        "checks": results,
    }


if __name__ == "__main__":
    print(json.dumps(run_audit(), indent=2))
