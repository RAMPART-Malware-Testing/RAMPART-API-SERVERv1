"""Weighted danger score derived from tool evidence.

When the AI synthesis step is unavailable, a report would otherwise have no
`score` at all - which silently drops the file out of every average on the
dashboard. This module produces a score from what the tools *did* return, and
labels it `tools` so the UI never presents it as an AI verdict.

Weights sum to 1.0 across all tools but are renormalised over the tools that
actually ran, so a VirusTotal-only analysis is not diluted by three
unavailable scores.
"""

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
    if score != score:  # NaN
        return None
    return max(0.0, min(score, MAX_SCORE))


def evidence_score(scores: dict) -> float | None:
    """Weighted average over the tools that produced a score, or None if none did.

    A tool that was skipped or failed contributes nothing and is not counted
    against the ones that did run - that is what keeps a VirusTotal-only result
    from reading as artificially low.
    """
    usable = {
        tool: _as_score(value)
        for tool, value in (scores or {}).items()
        if _as_score(value) is not None
    }
    if not usable:
        return None

    total_weight = sum(TOOL_WEIGHTS.get(tool, 0.0) for tool in usable)
    if total_weight <= 0:
        # Unknown tools carry no declared weight; fall back to an even split
        # rather than returning a number built from nothing.
        return round(sum(usable.values()) / len(usable), 2)

    weighted = sum(usable[tool] * TOOL_WEIGHTS.get(tool, 0.0) for tool in usable)
    return round(weighted / total_weight, 2)


def risk_level_for(score: float | None) -> str | None:
    """The same 0-29 / 30-59 / 60-79 / 80-100 bands the dashboard renders."""
    if score is None:
        return None
    if score < 30:
        return "Low"
    if score < 60:
        return "Caution"
    if score < 80:
        return "High"
    return "Critical"