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