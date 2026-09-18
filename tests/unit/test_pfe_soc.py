"""Connecteurs PFE : TheHive, STIX, ATT&CK auto, audit PCI."""

from detection.hive.case_manager import list_cases, open_case
from detection.intel.enricher import enrich
from detection.pipeline import handle_alerts
from detection.sigma.mappings.generate_navigator import generate_from_alerts
from scripts.pci_audit import run_audit


def test_hive_case_dedup(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUREPAY_HIVE_CASES", str(tmp_path / "cases.jsonl"))
    alert = {"title": "card testing", "severity": "critical", "rule_id": "r1", "source_ip": "203.0.113.9", "mitre": ["T1657"]}
    first = open_case(alert)
    second = open_case(alert)
    assert first["id"] == second["id"]
    assert len(list_cases()) == 1


def test_stix_enrich_mitre():
    result = enrich({"source_ip": "203.0.113.10", "mitre": ["T1657"]})
    assert "Financial Theft" in result["opencti_matches"]


def test_navigator_auto(tmp_path, monkeypatch):
    out = tmp_path / "layer.json"
    monkeypatch.setenv("SECUREPAY_NAVIGATOR_OUT", str(out))
    layer = generate_from_alerts(
        [{"title": "x", "mitre": ["T1657"], "source_ip": "203.0.113.1"}]
    )
    assert layer["techniques"][0]["techniqueID"] == "T1657"
    assert out.exists()


def test_pipeline_opens_case_and_blocks(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUREPAY_HIVE_CASES", str(tmp_path / "cases.jsonl"))
    monkeypatch.setenv("SECUREPAY_BLOCKSTATE", str(tmp_path / "state.json"))
    monkeypatch.setenv("SECUREPAY_BLOCKLIST", str(tmp_path / "blocks.jsonl"))
    monkeypatch.setenv("SECUREPAY_NAVIGATOR_OUT", str(tmp_path / "nav.json"))
    alert = {
        "title": "card testing attack",
        "severity": "critical",
        "rule_id": "carding",
        "source_ip": "198.51.100.20",
        "mitre": ["T1657"],
        "sample": {"scenario": "carding"},
    }
    result = handle_alerts([alert])
    assert result["soar"]
    assert result["hive_cases"]
    assert result["navigator_techniques"] >= 1


def test_pci_audit_score():
    report = run_audit()
    assert report["total"] >= 10
    assert report["passed"] == report["total"]
    assert report["score_pct"] == 100.0
