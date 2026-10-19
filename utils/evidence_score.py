from __future__ import annotations

TOOL_WEIGHTS: dict[str, float] = {
    "virustotal": 0.60,
    "mobsf": 0.15,
    "cape": 0.15,
    "ai": 0.10,
}

MAX_SCORE = 100.0


def _as_score(value) -> float | None:
    if value is None:
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if score != score:
        return None
    return max(0.0, min(score, MAX_SCORE))


def rampart_ai_score(value) -> float | None:
    if isinstance(value, dict):
        probability = value.get("malware_probability")
        if probability is None:
            return None
        try:
            return _as_score(float(probability) * 100)
        except (TypeError, ValueError):
            return None
    return _as_score(value)


def evidence_score(scores: dict) -> float | None:
    usable = {
        tool: _as_score(value)
        for tool, value in (scores or {}).items()
        if _as_score(value) is not None
    }
    if not usable:
        return None

    total_weight = sum(TOOL_WEIGHTS.get(tool, 0.0) for tool in usable)
    if total_weight <= 0:
        return round(sum(usable.values()) / len(usable), 2)

    weighted = sum(usable[tool] * TOOL_WEIGHTS.get(tool, 0.0) for tool in usable)
    return round(weighted / total_weight, 2)


def risk_level_for(score: float | None) -> str | None:
    if score is None:
        return None
    if score < 30:
        return "Low"
    if score < 60:
        return "Caution"
    if score < 80:
        return "High"
    return "Critical"


# Highest score reachable when nothing in the run confirmed the threat by observation.
# The cap is a ceiling, never a floor: a tool that already measured real danger keeps
# its score, and a sample whose malware is confirmed by observation (VirusTotal engines,
# a CAPE run that actually executed) is unaffected. It only stops an *unverified* score
# from claiming the High/Critical bands, whose whole meaning is "confirmed dangerous" -
# a sample nothing observed must read as "caution, unverified", never as "danger".
UNVERIFIED_SCORE_CAP = 59.0

# A tool's contribution counts as verified when it observed the sample behave rather
# than inferring from static properties alone.
VERIFIED_COVERAGE_STATES = {"complete"}


def apply_unverified_cap(
    score: float | None,
    *,
    malformed: bool = False,
) -> tuple[float | None, bool]:
    """Cap a score that rests on inference instead of observation.

    Returns the (possibly lowered) score and whether the cap actually applied, so the
    caller can tell the analyst the score is not a confirmed verdict.
    """
    if score is None:
        return None, False
    if malformed:
        return score, False
    if score <= UNVERIFIED_SCORE_CAP:
        return score, False
    return UNVERIFIED_SCORE_CAP, True


def coverage_is_incomplete(coverage: dict | None) -> bool:
    """True when every tool that contributed a score inferred it without observing behaviour."""
    contributing = {
        tool: state
        for tool, state in (coverage or {}).items()
        if state in VERIFIED_COVERAGE_STATES or state == "incomplete"
    }
    if not contributing:
        return False
    return all(state != "complete" for state in contributing.values())