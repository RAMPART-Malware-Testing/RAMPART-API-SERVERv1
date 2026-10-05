import os
import httpx
import json

from utils.evidence_score import evidence_score, risk_level_for


def apply_gemini_assessment(report, assessment: dict) -> None:
    report.score = assessment["danger_score"]
    report.score_source = "gemini"
    report.risk_level = assessment["risk_level"]
    report.recommendation = assessment["recommendation"]
    report.analysis_summary = assessment["summary"]
    report.risk_indicators = assessment["key_evidence"]
    report.gemini_recommendation = assessment["verdict"]


def apply_evidence_fallback(report) -> None:
    """Give a report a score from tool evidence when the AI step did not run.

    Without this the report keeps a NULL `score`, which drops it out of every
    average on the dashboard - the file was analysed, it just never got graded.
    The score is tagged `tools` so it is never shown as an AI verdict.
    """
    computed = evidence_score({
        "virustotal": report.virustotal_score,
        "mobsf": report.mobsf_score,
        "cape": report.cape_score,
        "ai": report.rampart_score,
    })
    if computed is None:
        return
    report.score = computed
    report.score_source = "tools"
    report.risk_level = report.risk_level or risk_level_for(computed)
    if not report.analysis_summary:
        report.analysis_summary = (
            "คะแนนคำนวณจากหลักฐานของเครื่องมือที่ทำงานสำเร็จ "
            "เนื่องจากการวิเคราะห์ด้วย AI ไม่สำเร็จ"
        )

def map_final_data_to_report(final_data: dict) -> dict:
    """
    จับคู่ข้อมูลจาก Gemini ให้ตรงกับคอลัมน์ใน Database
    """
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
    """
    พยากรณ์ความน่าจะเป็นของมัลแวร์ด้วย RampartAI
    """
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
