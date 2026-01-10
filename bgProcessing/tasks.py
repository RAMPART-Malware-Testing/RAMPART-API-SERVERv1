from bgProcessing.celery_app import celery_app
from Calling.VirusTotal import VirusTotal
from Calling.GeminiAPI import GeminiAPI
from Calling.MobSF import MobSFCall
from Calling.CAPE import CAPEAnalyzer
import time
import json
import os
import redis
from dotenv import load_dotenv

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
def analyze_malware_task(self, file_path: str, file_hashes: dict, total_size: int, analysis_tool: str, previous_results: dict = None, cape_task_id=None):
    print(total_size)
    print(type(total_size))

    results = previous_results if previous_results else {}
    md5 = file_hashes.get('md5', '')

    print(results)
    
    # ---------------------------------------------------------
    # PART 1: VirusTotal (Run Once)
    # ---------------------------------------------------------
    if "virustotal" not in results and "vt_skipped" not in results:
        vt = VirusTotal()
        print(f"[{self.request.id}] Starting VT Analysis: {md5}")
        
        if total_size > VIRUSTOTAL_MAX_SIZE:
            print("File too large for VT upload. Checking hash only.")
            rp = vt.get_report_by_hash(md5)
            print(f"rp : {rp}")
            if rp['success']: results["virustotal"] = rp["data"]
            else: results["vt_skipped"] = True
        else:
            # Upload & Check
            res = vt.upload_file(file_path=file_path)
            if res["success"]:
                try:
                    time.sleep(5) # VT รอแปปเดียว
                    id_b64 = res['data']['data']['id']
                    rp = vt.get_report_by_base64(id_b64)
                    if rp['success']: results["virustotal"] = rp["data"]
                except: pass
            else:
                results["vt_skipped"] = True # Mark as done to prevent loop

    # ---------------------------------------------------------
    # PART 2: MobSF (Redis Lock + Fire & Forget)
    # ---------------------------------------------------------
    if analysis_tool == "mobsf":
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
                            results["mobsf_error"] = "Failed to trigger scan"
                    else:
                        results["mobsf_error"] = "Failed to upload"

    # ---------------------------------------------------------
    # PART 3: CAPE (Check -> Create -> Poll)
    # ---------------------------------------------------------
    elif analysis_tool == "cape":
        cape = CAPEAnalyzer()
        
        if cape_task_id is None:
            # 3.1 First time / Check exist
            print(f"[CAPE] Checking/Submitting file...")
            ckid = cape.cheack_analyer(file_path)
            
            target_id = None
            if ckid and len(ckid) > 0:
                target_id = ckid[0].get('id')
                print(f"[CAPE] Found existing ID: {target_id}")
            else:
                res = cape.create_file_task(file_path, machine="win10")
                target_id = res.get('task_id')
                print(f"[CAPE] Created new task ID: {target_id}")

            if target_id:
                print(f"[CAPE] Waiting for analysis... (Retry in 60s)")
                # [FIXED] มี args=[] อยู่แล้ว ดีมาก
                raise self.retry(
                    countdown=60,
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
            # 3.2 Polling
            print(f"[CAPE] Polling ID: {cape_task_id}")
            status = cape.get_task_status(cape_task_id)
            print(status)
            state = status.get('data', 'unknown') if status.get('data') else 'error'
            
            if state == 'reported':
                print("[CAPE] Finished!")
                rp = cape.get_report(cape_task_id)
                if rp['status'] == 'success':
                    results["cape"] = rp['data']
                else:
                    results["cape_error"] = "Report fetch failed"
            elif state in ['failed_analysis', 'error']:
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

    return {"status": "success", "tool": analysis_tool, "final_file": "z-report4-gemini.json"}