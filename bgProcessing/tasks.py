from bgProcessing.celery_app import celery_app
from Calling.VirusTotal import VirusTotal
import time
import json

# Decorator @celery_app.task เปลี่ยนฟังก์ชันธรรมดาให้เป็น Task
@celery_app.task(bind=True)
def analyze_malware_task(self, file_path: str, file_hashes:dict, tools: list):
    print(f"[{self.request.id}] เริ่มวิเคราะห์ไฟล์: {file_path} ด้วยเครื่องมือ: {tools} file_hash256: {file_hashes.get('sha256')}")
    
    results = {}

    # try:
    if "virustotal" in tools:
        vt = VirusTotal()
        res = vt.upload_file(file_path=file_path)
        print(f"response upload: {res}")
        if res["success"]:
            id_b64 = ""
            try:
                id_b64 = res['data']['data']['id']
            except:pass
            print(f"id_b64 : {id_b64}")
            time.sleep(5)
            rp = vt.get_report_by_base64(id_b64)
            print(f"Response GET Report : {rp}")
            if rp['success']:
                results["virustotal"] = rp["data"]

    # --- 2. จำลองการส่งไป MobSF ---
    if "mobsf" in tools:
        # call_mobsf_function(file_path)
        results["mobsf"] = {"score": 50, "risk": "medium"}

    # --- 3. จำลองการส่งไป CAPE ---
    if "cape" in tools:
        results["cape"] = {"behavior": "suspicious"}

    with open('LLM-REPORT.json','w',encoding='utf-8') as wf:
        wf.write(json.dumps(results,ensure_ascii=False, indent=4))
        wf.close()

    return {
        "status": "completed",
        "file_path": file_path,
        "results": results
    }

    # except Exception as e:
    #     return {"status": "failed", "error": str(e)}