"""Tests Compliance as Code (Phase 3) — inventaire PCI-DSS + évaluation."""

from __future__ import annotations

from pathlib import Path

from compliance.assess import assess, load_controls

CONTROLS = Path(__file__).resolve().parents[2] / "compliance" / "controls.yaml"


def test_load_controls_yaml():
    controls = load_controls(CONTROLS)
    assert len(controls) >= 10
    assert "PCI-1" in controls
    assert "PCI-8.4.2" in controls


def test_all_evidence_paths_resolve():
    controls = load_controls(CONTROLS)
    from compliance.assess import _resolve

    for cid, control in controls.items():
        for evidence in control["evidence"]:
            assert _resolve(Path(evidence)), f"{cid} -> preuve manquante: {evidence}"


def test_assess_reports_pci_requirements():
    report = assess()
    assert report["framework"] == "PCI-DSS v4.0.1"
    assert report["summary"]["fail"] == 0, report["summary"]
    assert report["summary"]["pass"] == report["summary"]["total"]
    assert report["summary"]["coverage"] == "100%"


def test_assess_json_serializable():
    import json

    report = assess()
    json.dumps(report)
    assert "disclaimer" in report