"""Unit tests for the unverified-coverage score cap.

A score built only from tools that inferred danger (a sandbox that never ran the sample,
static properties) must not reach the High/Critical bands, whose meaning is "confirmed
dangerous". The cap is a ceiling only: it never raises a score, never touches a verdict
that something actually confirmed, and never fires when coverage was not supplied.

Run from the repo root:

    venv/bin/python -m pytest tests/test_evidence_score.py -v
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from utils.evidence_score import (
    UNVERIFIED_SCORE_CAP,
    apply_unverified_cap,
    coverage_is_incomplete,
    risk_level_for,
)


def test_incomplete_coverage_caps_a_critical_score_into_caution():
    capped, applied = apply_unverified_cap(95.0)
    assert capped == UNVERIFIED_SCORE_CAP
    assert capped < 60
    assert applied is True
    assert risk_level_for(capped) == "Caution"


def test_the_cap_boundary_is_exactly_the_caution_ceiling():
    capped, applied = apply_unverified_cap(59.0)
    assert (capped, applied) == (59.0, False)
    capped, applied = apply_unverified_cap(59.5)
    assert (capped, applied) == (UNVERIFIED_SCORE_CAP, True)


def test_a_score_below_the_cap_is_never_raised():
    capped, applied = apply_unverified_cap(12.0)
    assert (capped, applied) == (12.0, False)


def test_malformed_verdict_is_left_for_the_schema_to_reject():
    capped, applied = apply_unverified_cap(95.0, malformed=True)
    assert (capped, applied) == (95.0, False)


def test_no_score_and_no_coverage_are_both_no_ops():
    assert apply_unverified_cap(None) == (None, False)
    assert coverage_is_incomplete(None) is False
    assert coverage_is_incomplete({}) is False


def test_complete_coverage_means_the_score_is_verified():
    assert coverage_is_incomplete({"cape": "complete"}) is False


def test_a_single_incomplete_contributor_is_enough_to_flag_the_run():
    assert coverage_is_incomplete({"cape": "incomplete"}) is True


def test_an_absent_tool_does_not_count_either_way():
    """None is "no report to judge", not "incomplete"."""
    assert coverage_is_incomplete({"cape": None}) is False


def test_tools_that_are_not_scored_are_ignored():
    # mobsf/ai states are not part of this vocabulary; only scored contributors matter.
    assert coverage_is_incomplete({"cape": "complete", "mobsf": "unavailable"}) is False


def test_cape_coverage_state_reads_a_real_report(tmp_path):
    import json

    from bgProcessing.task_utils import cape_coverage_state
    from tests.test_cape_run_quality import BLOCKED_LOG, _report

    complete = tmp_path / "cape-complete.json"
    complete.write_text(json.dumps(_report()), encoding="utf-8")
    assert cape_coverage_state(str(complete)) == "complete"

    blocked = tmp_path / "cape-blocked.json"
    blocked.write_text(
        json.dumps(_report(debug={"errors": [], "log": BLOCKED_LOG}, behavior={"processes": []})),
        encoding="utf-8",
    )
    assert cape_coverage_state(str(blocked)) == "incomplete"

    assert cape_coverage_state(None) is None
    assert cape_coverage_state(str(tmp_path / "absent.json")) is None


def test_gemini_assessment_is_capped_only_for_incomplete_coverage():
    from bgProcessing.task_utils import apply_gemini_assessment

    class _Report:
        pass

    assessment = {
        "danger_score": 92.0,
        "risk_level": "Critical",
        "recommendation": "block",
        "summary": "static only",
        "key_evidence": ["vssadmin delete shadows"],
        "verdict": "Malicious",
    }

    # A Critical verdict whose only support is static/inferred evidence is capped: the
    # platform cannot call a sample "danger" when nothing observed it behave.
    incomplete = _Report()
    apply_gemini_assessment(incomplete, assessment, {"cape": "incomplete"})
    assert incomplete.score == UNVERIFIED_SCORE_CAP
    assert incomplete.risk_level == "Caution"
    assert incomplete.score_source == "gemini_capped"

    # With no coverage information at all, the verdict stands as the model gave it.
    unscoped = _Report()
    apply_gemini_assessment(unscoped, assessment, None)
    assert unscoped.score == 92.0
    assert unscoped.risk_level == "Critical"
    assert unscoped.score_source == "gemini"


def test_evidence_fallback_is_capped_and_explains_itself():
    from bgProcessing.task_utils import apply_evidence_fallback

    class _Report:
        virustotal_score = None
        mobsf_score = None
        cape_score = 95.0
        rampart_ai_score = None
        risk_level = None
        analysis_summary = None

    report = _Report()
    apply_evidence_fallback(report, {"cape": "incomplete"})
    assert report.score == UNVERIFIED_SCORE_CAP
    assert report.risk_level == "Caution"
    assert report.score_source == "tools_capped"
    assert "ไม่ครบถ้วน" in report.analysis_summary
