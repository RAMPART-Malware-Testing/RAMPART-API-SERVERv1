import os
import httpx
import json

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