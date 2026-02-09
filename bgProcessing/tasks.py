from sqlalchemy import select
from bgProcessing.celery_app import celery_app
from calling.VirusTotal import VirusTotal
from calling.GeminiAPI import GeminiAPI
from calling.MobSF import MobSFCall
from calling.CAPE import CAPEAnalyzer
import time
import json
import os
import redis
from dotenv import load_dotenv
from celery.exceptions import Retry
from sqlalchemy.exc import SQLAlchemyError

from cores.models_class import Analysis, Reports
from cores.sync_pg_db import SyncSessionLocal

load_dotenv()

# Config
VIRUSTOTAL_MAX_SIZE = 32 * 1024 * 1024
REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = os.environ.get("REDIS_PORT", "6379")
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", "")

# สร้าง URL แบบมี Password (ถ้ามี)
if REDIS_PASSWORD:
    REDIS_URL = f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/0"
else:
    REDIS_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/0"

# สร้าง Client เชื่อมต่อ Redis
redis_client = redis.StrictRedis.from_url(REDIS_URL)

@celery_app.task(bind=True, max_retries=100) 
def analyze_malware_task(self, analy_id: str, file_path: str, file_hashes: dict, total_size: int, analysis_tool: str, previous_results: dict = None, cape_task_id=None):
    db = SyncSessionLocal()
    analy = None
    try:
        stmt = select(Analysis).where(Analysis.aid == analy_id)
        analy = db.execute(stmt).scalar_one_or_none()

        if not analy:
            return { "success": False, "task_id": f"Analysis not found for task_id={self.request.id}" }

        analy.status = "processing"
        analy.task_id = self.request.id
        db.commit()

        # ถ้าไม่อยากให้ log งงอาจจเพิ่มตรวจสอบ  PREVIOUS ว่ามันทำซ้ำไหม
        print(f"#######################[ {self.request.id} ]#######################")
        md5 = file_hashes.get('md5', '')
        # เอาผลการวิเคราะห์เดิมเก็บมา ถ้าไม่มีจะได้ {} แต่ถ้ามีจะไม่วิเคราะห์ซ้ำ
        results = previous_results if previous_results else {}
        PREVIOUS = []
        if isinstance(previous_results, dict):
            PREVIOUS = list(previous_results.keys())
        print(f"REPORTED PREVIOUS:{PREVIOUS}")
        
        # ---------------------------------------------------------
        # PART 1: VirusTotal (Run Once) !!! cape_task_id is None and  สำคัญมากเอาไว้สำหรับ retry cape ในกณี รอการวิเคราะห์ต้องมีไม่งั้นจะเปลือง VT + Mobsf เพราะวนลูปจนกว่า cape จำเสร็จ
        # ---------------------------------------------------------
        if cape_task_id is None and "virustotal" not in results and "vt_skipped" not in results:
            vt = VirusTotal()
            print(f"[VT] Starting VT Analysis: {md5}")
            
            if total_size > VIRUSTOTAL_MAX_SIZE:
                print("[VT] File too large for VT upload. Checking hash only.")
                rp = vt.get_report_by_hash(md5)
                if rp['success']: 
                    print(f"[VT] get report success")
                    results["virustotal"] = rp["data"]
                else:
                    print(f"[VT] vt_skipped") 
                    results["vt_skipped"] = True
            else:
                # Upload & Check
                res = vt.upload_file(file_path=file_path)
                if res["success"]:
                    try:
                        time.sleep(5) # VT รอแปปเดียว
                        id_b64 = res['data']['data']['id']
                        rp = vt.get_report_by_base64(id_b64)
                        if rp['success']: 
                            print(f"[VT] get report success")
                            results["virustotal"] = rp["data"]
                    except: 
                        print(f"[VT] get report failed")
                else:
                    print(f"[VT] vt_skipped")
                    results["vt_skipped"] = True # Mark as done to prevent loop

        # ---------------------------------------------------------
        # PART 2: MobSF (Redis Lock + Fire & Forget)
        # ---------------------------------------------------------
        if cape_task_id is None and "mobsf" in analysis_tool:
            mobsf = MobSFCall()
            redis_key = f"mobsf_status:{md5}"
            
            # 2.1 Check Report
            if "mobsf_report" not in results:
                report_check = mobsf.generate_json_report(md5)
                
                if report_check['success']:
                    print(f"[MobSF] Report Found!")
                    results["mobsf_report"] = report_check['data']
                    redis_client.delete(redis_key) # Clear lock
                
                else:
                    # 2.2 Check Redis Lock
                    status = redis_client.get(redis_key)
                    if status and status.decode() == 'scanning':
                        print(f"[MobSF] Scanning in progress (Redis locked). Retrying in 30s...")
                        # [FIXED] เพิ่ม args=[]
                        raise self.retry(
                            countdown=30, 
                            args=[], 
                            kwargs={
                                'file_path': file_path, 'file_hashes': file_hashes, 
                                'total_size': total_size, 'analysis_tool': analysis_tool,
                                'previous_results': results
                            }
                        )
                    
                    # 2.3 Upload & Scan
                    else:
                        print(f"[MobSF] Uploading and starting scan...")
                        up_res = mobsf.upload_file(file_path)
                        if up_res['success']:
                            # Scan with Timeout 5s (Fire & Forget)
                            scan_res = mobsf.scan_uploaded_file(md5, timeout=5)
                            
                            if scan_res['success']:
                                # Set Lock for 1 hour
                                redis_client.setex(redis_key, 3600, 'scanning')
                                print(f"[MobSF] Scan triggered. Locking Redis and waiting...")
                                # [FIXED] เพิ่ม args=[]
                                raise self.retry(
                                    countdown=30, 
                                    args=[],
                                    kwargs={
                                        'file_path': file_path, 'file_hashes': file_hashes, 
                                        'total_size': total_size, 'analysis_tool': analysis_tool,
                                        'previous_results': results
                                    }
                                )
                            else:
                                print(f"[MobSF] Failed to trigger scan")
                                results["mobsf_error"] = "Failed to trigger scan"
                        else:
                            print(f"[MobSF] Failed to upload")
                            results["mobsf_error"] = "Failed to upload file not support"

        # ---------------------------------------------------------
        # PART 3: CAPE (Check -> Create -> Poll)
        # ---------------------------------------------------------
        if "cape" in analysis_tool:
            cape = CAPEAnalyzer()
            # cape_task_id จะได้ตอนที่ไม่มี ID จะสั่งรันซ้ำในกรณีกำลังวิเคราะห์ 
            if cape_task_id is None:
                # 3.1 First time / Check exist
                print(f"[CAPE] Checking/Submitting file...")
                ckid = cape.cheack_analyer(file_path)
                
                target_id = None
                countdown = 60
                if ckid and len(ckid) > 0:
                    target_id = ckid[0].get('id')
                    countdown = 1
                    print(f"[CAPE] Found existing ID: {target_id}")
                else:
                    res = cape.create_file_task(file_path, machine="win10")
                    target_id = res.get('task_id')
                    print(f"[CAPE] Created new task ID: {target_id}")

                if target_id:
                    print(f"[CAPE] Waiting for analysis/generate report... (Retry in 60s)")
                    #  ถ้ามี ID จะสั่งรันใหม่อีกรอบ ตรงนี้สำคัญต้องตรวจสอบ VT+Mobsf เพื่อให้ทำซ้ำตาม CAPE
                    raise self.retry(
                        countdown=countdown,
                        args=[],
                        kwargs={
                            'file_path': file_path,
                            'file_hashes': file_hashes,
                            'total_size': total_size,
                            'analysis_tool': analysis_tool,
                            'previous_results': results,
                            'cape_task_id': target_id
                        }
                    )
                else:
                    results["cape_error"] = "Failed to get CAPE Task ID"

            else:
                print(f"[CAPE] Polling ID: {cape_task_id}")
                status = cape.get_task_status(cape_task_id)
                print(f"[CAPE] {status}")
                state = status.get('data', 'unknown') if status.get('data') else 'error'
                
                if state == 'reported':
                    print("[CAPE] Finished!")
                    rp = cape.get_report(cape_task_id)
                    if rp['status'] == 'success':
                        print(f"[CAPE] Report fetch report success")
                        results["cape"] = rp['data']
                    else:
                        print(f"[CAPE] Report fetch failed")
                        results["cape_error"] = "Report fetch report failed"
                elif state in ['failed_analysis', 'error']:
                    print(f"[CAPE] Analysis failed with state: {state}")
                    results["cape_error"] = f"Analysis failed with state: {state}"
                else:
                    print(f"[CAPE] Status: {state}. Retrying in 30s...")
                    raise self.retry(
                        countdown=30, 
                        args=[],
                        kwargs={
                            'file_path': file_path, 'file_hashes': file_hashes, 
                            'total_size': total_size, 'analysis_tool': analysis_tool,
                            'previous_results': results,
                            'cape_task_id': cape_task_id
                        }
                    )

        # ---------------------------------------------------------
        # PART 4: Save & Gemini
        # ---------------------------------------------------------
        # Save Intermediate
        try:
            with open('z-report3-result.json', 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=4)
        except: pass

        print("[Gemini] Sending data to AI...")
        gemini = GeminiAPI()
        response = gemini.AnalysisGemini(results)
        
        # Save Final
        final_data = response if isinstance(response, dict) else {"raw": response}
        if isinstance(response, str):
            try: final_data = json.loads(response.replace("```json","").replace("```",""))
            except: pass
        try:
            with open('z-report4-gemini.json', 'w', encoding='utf-8') as f:
                json.dump(final_data, f, ensure_ascii=False, indent=4)
        except: pass
        
        report_data = map_final_data_to_report(final_data)
        stmt = select(Reports).where(Reports.aid == analy.aid)
        report = db.execute(stmt).scalar_one_or_none()

        if report:
            # UPDATE
            for key, value in report_data.items():
                setattr(report, key, value)
        else:
            # INSERT
            report = Reports(
                aid=analy.aid,
                **report_data
            )
            db.add(report)

        analy.status = "success"
        db.commit()
        return {"success": True, "task_id":f"Analysis Successfully. : {self.request.id}"}
    except Retry:
        raise
    except Exception as e:
        print(f"ERROR TASK ==> {e}")
        try:
            db.rollback()
            if analy:
                analy.status = "failed"
                db.commit()
        except:pass
        raise
    finally:
        db.close()

def map_final_data_to_report(final_data: dict) -> dict:
    return {
        "package": final_data.get("app_metadata", {}).get("package"),
        "type": final_data.get("app_metadata", {}).get("type"),

        "score": final_data.get("security_assessment", {}).get("score"),
        "risk_level": final_data.get("security_assessment", {}).get("risk_level"),
        "color": final_data.get("security_assessment", {}).get("verdict_color"),

        "recommendation": final_data.get("user_recommendation"),
        "analysis_summary": final_data.get("analysis_summary"),
        "risk_indicators": final_data.get("risk_indicators"),

        # ถ้าอยากให้ rampart_score = score
        # "rampart_score": final_data.get("security_assessment", {}).get("score"),
    }
