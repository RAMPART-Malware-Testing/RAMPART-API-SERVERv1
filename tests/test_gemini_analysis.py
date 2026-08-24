import json

from bgProcessing.report_evidence import build_gemini_evidence
from bgProcessing.task_utils import apply_gemini_assessment


def test_compact_evidence_excludes_large_raw_fields(tmp_path):
    vt_path = tmp_path / "vt.json"
    mobsf_path = tmp_path / "mobsf.json"
    cape_path = tmp_path / "cape.json"
    vt_path.write_text(json.dumps({
        "data": {"attributes": {
            "meaningful_name": "sample.apk",
            "type_description": "Android",
            "last_analysis_stats": {"malicious": 0, "undetected": 60},
            "last_analysis_results": {},
        }}
    }), encoding="utf-8")
    mobsf_path.write_text(json.dumps({
        "app_name": "Sample",
        "appsec": {"high": [{"title": "Weak TLS", "description": "x" * 5000}]},
        "strings": ["secret"] * 10000,
        "files": ["file"] * 10000,
    }), encoding="utf-8")
    cape_path.write_text(json.dumps({
        "malscore": 7.5,
        "malstatus": "Malicious",
        "signatures": [{"name": "injection", "severity": 3, "description": "RWX memory"}],
        "procmemory": ["huge"] * 10000,
    }), encoding="utf-8")

    evidence = build_gemini_evidence(vt_path, mobsf_path, cape_path)
    encoded = json.dumps(evidence)

    assert evidence["virustotal"]["stats"]["malicious"] == 0
    assert evidence["mobsf"]["high_findings"][0]["title"] == "Weak TLS"
    assert evidence["cape"]["danger_score"] == 75
    assert "strings" not in encoded
    assert "procmemory" not in encoded
    assert len(encoded) < 15_000


def test_skipped_report_is_explicitly_represented(tmp_path):
    vt_path = tmp_path / "vt.json"
    vt_path.write_text('{"data":{"attributes":{"last_analysis_stats":{}}}}', encoding="utf-8")

    evidence = build_gemini_evidence(vt_path, None, None)

    assert evidence["mobsf"] == {"status": "not_available"}
    assert evidence["cape"] == {"status": "not_available"}


def test_gemini_evidence_never_includes_rampart_ai(tmp_path):
    """RampartAI is RAMPART's own in-house model, not a third-party
    signal - its output must never be exposed to or referenced by the
    external Gemini LLM, even implicitly via a stray dict key."""
    vt_path = tmp_path / "vt.json"
    mobsf_path = tmp_path / "mobsf.json"
    cape_path = tmp_path / "cape.json"
    vt_path.write_text('{"data":{"attributes":{"last_analysis_stats":{}}}}', encoding="utf-8")
    mobsf_path.write_text('{"app_name": "Sample", "appsec": {}}', encoding="utf-8")
    cape_path.write_text('{"malscore": 0}', encoding="utf-8")

    evidence = build_gemini_evidence(vt_path, mobsf_path, cape_path)

    assert "rampart_ai" not in evidence
    assert "rampart_ai" not in json.dumps(evidence)


def test_gemini_assessment_maps_to_report_columns():
    class Report:
        pass

    report = Report()
    assessment = {
        "danger_score": 72,
        "risk_level": "High",
        "verdict": "Behavioral evidence indicates high risk.",
        "summary": "CAPE found injection behavior while VirusTotal found no detections.",
        "recommendation": "Do not execute outside an isolated environment.",
        "key_evidence": ["CAPE: injection_rwx"],
    }

    apply_gemini_assessment(report, assessment)

    assert report.score == 72
    assert report.risk_level == "High"
    assert report.gemini_recommendation == assessment["verdict"]
    assert report.risk_indicators == assessment["key_evidence"]
