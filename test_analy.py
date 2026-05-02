import os
import json
import time
import httpx
import redis
import asyncio
import uuid
from dotenv import load_dotenv

from calling.VirusTotal import VirusTotal
# from calling.GeminiAPI import GeminiAPI
# from calling.MobSF import MobSFCall
# from calling.CAPE import CAPEAnalyzer
# from cores.models_class import Analysis, Reports
# from cores.sync_pg_db import SyncSessionLocal

load_dotenv()

VIRUSTOTAL_MAX_SIZE = 32 * 1024 * 1024
REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = os.environ.get("REDIS_PORT", "6379")
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", "")

if REDIS_PASSWORD:
    REDIS_URL = f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/0"
else:
    REDIS_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/0"

redis_client = redis.StrictRedis.from_url(REDIS_URL)

# ─── Helpers ──────────────────────────────────────────────────────────────────
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

async def predicRampartAI(path_mobsf_report: str) -> dict:
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
    except json.JSONDecodeError as e:
        return {"success": False, "message": f"Invalid JSON response: {e}"}
    except Exception as e:
        return {"success": False, "message": str(e)}

# ─── Main Function (Local Testing) ─────────────────────────────────────────────
def run_analysis_local(
    file_path: str,
    file_hashes: dict,
    total_size: int,
    analysis_tool: str
):
    """
    ฟังก์ชันสำหรับรันทดสอบแบบ Synchronous แทน Celery Task
    """
    db = SyncSessionLocal()
    analy = None
    mock_task_id = str(uuid.uuid4()) # สร้าง UUID จำลองแทน self.request.id
    results = {}

    try:
        sha256 = file_hashes.get('sha256', '')
        md5    = file_hashes.get('md5', '')

        stmt = select(Analysis).where(Analysis.file_hash == sha256).limit(1)
        analy = db.execute(stmt).scalar_one_or_none()

        if not analy:
            print(f"[ERROR] Analysis not found for hash={sha256}")
            return {"success": False, "message": f"Analysis not found for hash={sha256}"}

        print(f"#######################[ LOCAL TASK: {mock_task_id} ]#######################")

        # ── VirusTotal ────────────────────────────────────────────────────────
        if "virustotal" in analysis_tool or "virustotal" not in results:
            if "virustotal" not in analysis_tool:
                analysis_tool += ",virustotal"
            
            vt = VirusTotal()
            print(f"[VT] Starting VT Analysis: {md5}")

            if total_size > VIRUSTOTAL_MAX_SIZE:
                print("[VT] File too large. Checking hash only.")
                rp = vt.get_report_by_hash(md5)
                if rp['success']:
                    print("[VT] Report success")
                    results["virustotal"] = rp["data"]
                else:
                    print("[VT] vt_skipped")
                    results["vt_skipped"] = True
            else:
                res = vt.upload_file(file_path=file_path)
                if res["success"]:
                    try:
                        print("[VT] Upload success, waiting 5s for report...")
                        time.sleep(5)
                        id_b64 = res['data']['data']['id']
                        rp = vt.get_report_by_base64(id_b64)
                        if rp['success']:
                            print("[VT] Report success")
                            results["virustotal"] = rp["data"]
                    except Exception as e:
                        print(f"[VT] Report fetch failed: {e}")
                else:
                    print("[VT] vt_skipped")
                    results["vt_skipped"] = True

        # ── MobSF (Polling Loop แทน Celery Retry) ──────────────────────────────
        if "mobsf" in analysis_tool:
            mobsf = MobSFCall()
            redis_key = f"mobsf_status:{md5}"
            
            while True:
                report_check = mobsf.generate_json_report(md5)
                if report_check['success']:
                    print("[MobSF] Report Found!")
                    results["mobsf_report"] = report_check['data']
                    redis_client.delete(redis_key)
                    break # หลุดออกจาก Loop เมื่อได้ Report
                else:
                    status = redis_client.get(redis_key)
                    if status and status.decode() == 'scanning':
                        print("[MobSF] Scanning in progress. Waiting 30s...")
                        time.sleep(30)
                    else:
                        print("[MobSF] Uploading and starting scan...")
                        up_res = mobsf.upload_file(file_path)
                        if up_res['success']:
                            scan_res = mobsf.scan_uploaded_file(md5, timeout=5)
                            if scan_res['success']:
                                redis_client.setex(redis_key, 3600, 'scanning')
                                print("[MobSF] Scan triggered. Waiting 30s...")
                                time.sleep(30)
                            else:
                                print("[MobSF] Failed to trigger scan")
                                results["mobsf_error"] = "Failed to trigger scan"
                                break
                        else:
                            print("[MobSF] Failed to upload. File not supported.")
                            results["mobsf_error"] = "Failed to upload file not support"
                            break

        # ── CAPE (Polling Loop แทน Celery Retry) ───────────────────────────────
        if "cape" in analysis_tool:
            cape = CAPEAnalyzer()
            print("[CAPE] Checking/Submitting file...")
            ckid = cape.cheack_analyer(file_path)
            target_id = None

            if ckid and len(ckid) > 0:
                target_id = ckid[0].get('id')
                print(f"[CAPE] Found existing ID: {target_id}")
            else:
                res = cape.create_file_task(file_path, machine="win10")
                target_id = res.get('task_id')
                print(f"[CAPE] Created new task ID: {target_id}")
                print("[CAPE] Waiting 60s for initial analysis...")
                time.sleep(60)

            if target_id:
                while True:
                    print(f"[CAPE] Polling ID: {target_id}")
                    status = cape.get_task_status(target_id)
                    state  = status.get('data', 'unknown') if status.get('data') else 'error'
                    print(f"[CAPE] State: {state}")

                    if state == 'reported':
                        print("[CAPE] Finished!")
                        rp = cape.get_report(target_id, md5)
                        analy.cape_id = target_id
                        if rp['status'] == 'success':
                            print("[CAPE] Report fetch success")
                            results["cape"] = rp['data']
                        else:
                            print("[CAPE] Report fetch failed")
                            results["cape_error"] = "Report fetch failed"
                        break
                    elif state in ['failed_analysis', 'error']:
                        print(f"[CAPE] Analysis failed: {state}")
                        results["cape_error"] = f"Analysis failed: {state}"
                        break
                    else:
                        print(f"[CAPE] Status: {state}. Waiting 30s...")
                        time.sleep(30)
            else:
                results["cape_error"] = "Failed to get CAPE Task ID"

        # บันทึกผลลัพธ์ดิบ
        os.makedirs("results", exist_ok=True)
        with open(f'results/{md5}.json', 'w', encoding='utf-8') as f:
            json.dump(results, f)

        # ── Gemini AI ─────────────────────────────────────────────────────────
        print("[Gemini] Sending data to AI...")
        gemini = GeminiAPI()
        response = gemini.AnalysisGemini(results)
        
        with open(f'results/test-gemini1.txt', 'w', encoding='utf-8') as f:
            f.write(response if isinstance(response, str) else str(response))
            
        final_data = response if isinstance(response, dict) else {"raw": response}
        if isinstance(response, str):
            try:
                final_data = json.loads(response.replace("```json", "").replace("```", ""))
            except Exception as e:
                print(f"[Gemini] Failed to parse JSON: {e}")

        with open(f'results/test-gemini2.json', 'w', encoding='utf-8') as f:
            json.dump(final_data, f)

        # ── RampartAI Predict (Retry Loop) ────────────────────────────────────
        if results.get('mobsf_report') and "rampart_ai" not in results:
            mobsf_report_path = os.path.join("reports", f'mobsf-{md5}.json')
            
            for attempt in range(1, 6): # ลองสูงสุด 5 ครั้ง
                print(f"[RampartAI] Predicting: {mobsf_report_path} (attempt {attempt}/5)")
                redic = asyncio.run(predicRampartAI(mobsf_report_path))

                if redic.get("success"):
                    print(f"[RampartAI] Prediction success: rampart_score={redic.get('rampart_score')}")
                    results["rampart_ai"] = redic
                    break # สำเร็จแล้วออกจาก Loop
                else:
                    print(f"[RampartAI] Failed: {redic.get('message')}")
                    if attempt < 5:
                        print("[RampartAI] Waiting 5s before retry...")
                        time.sleep(5)
                    else:
                        print("[RampartAI] Max retries exceeded, skipping...")
                        results["rampart_ai_error"] = redic.get("message")
            
        if results.get("rampart_ai", {}).get("success"):
            final_data["rampart_score"] = results["rampart_ai"].get("rampart_score")
            print(f"[RampartAI] rampart_score merged: {final_data.get('rampart_score')}")

        # ── Save Report ───────────────────────────────────────────────────────
        report_data = map_final_data_to_report(final_data)
        stmt   = select(Reports).where(Reports.rid == analy.rid)
        report = db.execute(stmt).scalar_one_or_none()

        if report:
            for key, value in report_data.items():
                setattr(report, key, value)
        else:
            report = Reports(**report_data)
            db.add(report)

        db.flush()

        # ── Sync duplicate analyses ───────────────────────────────────────────
        if sha256:
            stmt_all = select(Analysis).where(
                Analysis.file_hash == sha256,
                Analysis.aid != analy.aid
            )
            for dup in db.execute(stmt_all).scalars().all():
                dup.status  = "success"
                dup.task_id = mock_task_id
                dup.tools   = analysis_tool
                dup.rid     = report.rid
                print(f"[SYNC] Updated duplicate aid={dup.aid} rid={report.rid}")

        analy.status = "success"
        analy.tools  = analysis_tool
        analy.rid    = report.rid
        analy.md5    = md5
        analy.task_id = mock_task_id

        db.commit()
        print(f"[DONE] Analysis complete: {mock_task_id}")
        return {"success": True, "task_id": f"Analysis Successfully (Local): {mock_task_id}", "data": final_data}

    except Exception as e:
        print(f"[ERROR] Task failed: {e}")
        try:
            db.rollback()
            if analy:
                analy.status = "failed"
                db.commit()
        except:
            pass
        raise
    finally:
        db.close()


# ==========================================
# บล็อกสำหรับ Execute ทดสอบ
# ==========================================
if __name__ == "__main__":
    # ใส่พารามิเตอร์จำลองของคุณตรงนี้ครับ
    TEST_FILE_PATH = "./sample_malware.apk"
    TEST_FILE_HASHES = {
        "md5": "d41d8cd98f00b204e9800998ecf8427e", # เปลี่ยนเป็น MD5 จริง
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" # เปลี่ยนเป็น SHA256 ที่มีใน DB คุณ
    }
    TEST_TOTAL_SIZE = 1024 * 500 # 500 KB
    TEST_ANALYSIS_TOOL = "mobsf,cape" # ระบุ Tool ที่ต้องการเทส

    print("--- Starting Local Analysis Test ---")
    result = run_analysis_local(
        file_path=TEST_FILE_PATH,
        file_hashes=TEST_FILE_HASHES,
        total_size=TEST_TOTAL_SIZE,
        analysis_tool=TEST_ANALYSIS_TOOL
    )
    
    print("\n--- Final Output ---")
    print(json.dumps(result, indent=4))