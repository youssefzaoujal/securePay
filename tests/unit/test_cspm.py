"""CSPM — fixture CIS produit des CRITICAL (démo) ; Terraform scan ne crash pas."""

from pathlib import Path

from cspm.scanner import run_scan


def test_fixture_finds_public_s3_and_open_ssh():
    findings = run_scan(
        mode="fixture",
        fixture_path=Path("cspm/fixtures/aws_inventory.json"),
        terraform_dir=Path("infra/terraform"),
    )
    ids = {item["id"] for item in findings}
    assert "CIS-1.4" in ids
    assert "CIS-2.1.1" in ids
    assert "CIS-5.2" in ids
    assert "CIS-3.1" in ids
    assert any(item["severity"] == "CRITICAL" for item in findings)


def test_terraform_scan_runs():
    findings = run_scan(
        mode="terraform",
        fixture_path=Path("cspm/fixtures/aws_inventory.json"),
        terraform_dir=Path("infra/terraform"),
    )
    assert isinstance(findings, list)
