import os
import httpx
import json

from utils.evidence_score import (
    apply_unverified_cap,
    coverage_is_incomplete,
    evidence_score,
    rampart_ai_score,
    risk_level_for,
)


def cape_coverage_state(report_path: str | None) -> str | None:
    """Whether a CAPE report describes a run that actually observed the sample.

    Returns None when there is nothing to judge, so an absent tool never counts as
    evidence either way.
    """
    if not report_path:
        return None
    from pathlib import Path

    try:
        path = Path(report_path)
        if not path.is_file():
            return None
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    from bgProcessing.task_handlers import cape_run_quality

    try:
        quality = cape_run_quality(payload)
    except (AttributeError, TypeError, ValueError):
        return None
    return "complete" if quality.get("status") == "complete" else "incomplete"


def apply_gemini_assessment(report, assessment: dict, coverage: dict | None = None) -> None:
    score = assessment["danger_score"]
    if coverage_is_incomplete(coverage):
        capped, capped_applied = apply_unverified_cap(score)
    else:
        capped, capped_applied = score, False
    report.score = capped
    report.score_source = "gemini_capped" if capped_applied else "gemini"
    report.risk_level = risk_level_for(capped) if capped_applied else assessment["risk_level"]
    report.recommendation = assessment["recommendation"]
    report.analysis_summary = assessment["summary"]
    report.risk_indicators = assessment["key_evidence"]
    report.gemini_recommendation = assessment["verdict"]


def apply_evidence_fallback(report, coverage: dict | None = None) -> None:
    computed = evidence_score({
        "virustotal": report.virustotal_score,
        "mobsf": report.mobsf_score,
        "cape": report.cape_score,
        "ai": rampart_ai_score(report.rampart_ai_score),
    })
    if computed is None:
        return
    capped, capped_applied = (
        apply_unverified_cap(computed) if coverage_is_incomplete(coverage) else (computed, False)
    )
    report.score = capped
    report.score_source = "tools_capped" if capped_applied else "tools"
    report.risk_level = risk_level_for(capped)
    if capped_applied:
        report.analysis_summary = (
            "ผลวิเคราะห์ไม่ครบถ้วน — ไม่มีเครื่องมือใดยืนยันพฤติกรรมของไฟล์ได้จริง "
            "คะแนนจึงถูกจำกัดไว้ที่ระดับเฝ้าระวัง"
        )
    elif not report.analysis_summary:
        report.analysis_summary = (
            "คะแนนคำนวณจากหลักฐานของเครื่องมือที่ทำงานสำเร็จ "
            "เนื่องจากการวิเคราะห์ด้วย AI ไม่สำเร็จ"
        )

def map_final_data_to_report(final_data: dict) -> dict:
    return {
        "package":          final_data.get("app_metadata", {}).get("package"),
        "type":             final_data.get("app_metadata", {}).get("type"),
        "score":            final_data.get("security_assessment", {}).get("score"),
        "risk_level":       final_data.get("security_assessment", {}).get("risk_level"),
        "recommendation":   final_data.get("user_recommendation"),
        "analysis_summary": final_data.get("analysis_summary"),
        "risk_indicators":  final_data.get("risk_indicators"),
        "rampart_score":    final_data.get("rampart_score"),
    }

async def predict_rampart_ai(path_mobsf_report: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            with open(path_mobsf_report, 'rb') as f:
                res = await client.post(
                    f"{os.getenv('RAMPARTAI_URL')}/predict",
                    files={"file": (os.path.basename(path_mobsf_report), f, "application/json")},
                )
            result = res.json()
            print(f"[RampartAI] Response: {result}")
            return {
                "success": True,
                "rampart_score": result.get("malware_probability"),
                "prediction": result.get("prediction"),
            }
    except FileNotFoundError:
        return {"success": False, "message": f"File not found: {path_mobsf_report}"}
    except Exception as e:
        return {"success": False, "message": str(e)}
