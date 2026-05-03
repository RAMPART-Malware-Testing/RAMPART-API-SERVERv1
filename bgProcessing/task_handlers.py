import time
from calling.VirusTotal import VirusToTalAPI
# สามารถ import MobSF, CAPE, GeminiAPI เข้ามาเพิ่มได้ที่นี่ในอนาคต

VIRUSTOTAL_MAX_SIZE = 32 * 1024 * 1024

vt = VirusToTalAPI()

def handle_virustotal(file_path: str, md5: str, total_size: int, results: dict) -> dict:
    print(f"[VT] Starting VT Analysis: {md5}")
    if total_size > VIRUSTOTAL_MAX_SIZE:
        print("[VT] File too large. Checking hash only.")
        rp = vt.get_report_by_hash(md5)
        if rp.get('success'):
            print("[VT] Report success (Hash)")
            results["virustotal"] = rp["data"]
        else:
            print("[VT] vt_skipped")
            results["vt_skipped"] = True
    else:
        res = vt.upload_file(file_path=file_path)
        if res.get("success"):
            try:
                time.sleep(5)  # หน่วงเวลาเบื้องต้น (เดี๋ยวในอนาคตเราอาจปรับเป็น Queue)
                id_b64 = res['data']['data']['id']
                rp = vt.get_report_by_base64(id_b64)
                if rp.get('success'):
                    print("[VT] Report success (Upload)")
                    results["virustotal"] = rp["data"]
                else:
                    print("[VT] Report fetch failed after upload")
                    results["vt_skipped"] = True
            except Exception as e:
                print(f"[VT] Error during report fetch: {e}")
                results["vt_skipped"] = True
        else:
            print("[VT] vt_skipped (Upload Failed)")
            results["vt_skipped"] = True
            
    return results

# ในอนาคตเราจะเขียน def handle_mobsf(...) และ def handle_cape(...) ไว้ที่นี่ครับ