import os
import json
import time
import hashlib
from dotenv import load_dotenv

# นำเข้าเฉพาะคลาส VirusTotal ของคุณ
from calling.VirusTotal import VirusToTalAPI

load_dotenv()

VIRUSTOTAL_MAX_SIZE = 32 * 1024 * 1024

# ─── ฟังก์ชันใหม่สำหรับสกัดชนิดมัลแวร์ ────────────────────────────────────
def extract_malware_types(vt_data: dict) -> list:
    """
    สกัดรายชื่อ/ชนิดของมัลแวร์จาก Report ของ VirusTotal
    และตัดข้อมูลที่ซ้ำกันออก
    """
    if not vt_data:
        return []
        
    malicious_list = vt_data.get("threats_found", {}).get("malicious", [])
    extracted_types = set() # ใช้ set เพื่อป้องกันรายชื่อมัลแวร์ซ้ำกัน
    
    for threat in malicious_list:
        # รูปแบบข้อความจะเป็น "EngineName: MalwareType/Name"
        # เช่น "ESET-NOD32: Android/Spy.Banker.BGB trojan"
        if ":" in threat:
            # แยกข้อความด้วย ":" และเอาเฉพาะส่วนที่ 2 (index 1) มาใช้
            malware_name = threat.split(":", 1)[1].strip()
            extracted_types.add(malware_name)
        else:
            extracted_types.add(threat.strip())
            
    return list(extracted_types)
# ──────────────────────────────────────────────────────────────────

def calculate_hashes(file_path: str) -> dict:
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
            sha256_hash.update(chunk)

    return {
        "md5": md5_hash.hexdigest(),
        "sha256": sha256_hash.hexdigest()
    }

def run_virustotal_test(file_path: str):
    print(f"--- เริ่มต้นการทดสอบไฟล์: {file_path} ---")

    if not os.path.exists(file_path):
        print(f"[ERROR] ไม่พบไฟล์ที่ระบุ: {file_path}")
        return {"success": False, "message": "File not found"}

    file_hashes = calculate_hashes(file_path)
    md5 = file_hashes["md5"]
    sha256 = file_hashes["sha256"]
    total_size = os.path.getsize(file_path)

    print(f"[INFO] ขนาดไฟล์: {total_size} bytes")
    print(f"[INFO] MD5: {md5}")
    print(f"[INFO] SHA256: {sha256}")

    vt = VirusToTalAPI()
    results = {}

    print("\n[VT] กำลังตรวจสอบ Report จาก Hash...")
    rp = vt.get_report_by_hash(sha256)

    if rp.get('success'):
        print("[VT] พบ Report จาก Hash เรียบร้อยแล้ว ไม่ต้องอัปโหลดใหม่")
        results["virustotal"] = rp.get("data")
        # สกัดชนิดมัลแวร์
        results["extracted_malware_types"] = extract_malware_types(results["virustotal"])
    else:
        print("[VT] ไม่พบ Report จาก Hash")

        if total_size > VIRUSTOTAL_MAX_SIZE:
            print(f"[VT] ข้ามการอัปโหลดเนื่องจากไฟล์ใหญ่เกินไป ({total_size} bytes)")
            results["vt_skipped"] = True
            results["message"] = "File too large to upload, and no hash report found."
        else:
            print("[VT] กำลังอัปโหลดไฟล์เพื่อวิเคราะห์...")
            res = vt.upload_file(file_path=file_path)
            
            if res.get("success"):
                try:
                    print("[VT] อัปโหลดสำเร็จ รอ 15 วินาทีเพื่อให้ VT ประมวลผล...")
                    time.sleep(15) 
                    
                    id_b64 = res['data']['data']['id']
                    print(f"[VT] กำลังดึงผลลัพธ์ด้วย ID: {id_b64}...")
                    
                    new_rp = vt.get_report_by_base64(id_b64)
                    if new_rp.get('success'):
                        print("[VT] ได้รับผลการวิเคราะห์จากการอัปโหลดเรียบร้อย")
                        results["virustotal"] = new_rp.get("data")
                        # สกัดชนิดมัลแวร์
                        results["extracted_malware_types"] = extract_malware_types(results["virustotal"])
                    else:
                        print("[VT] ดึงผลลัพธ์ไม่ทัน (อาจต้องใช้เวลาประมวลผลนานกว่านี้)")
                        results["virustotal_upload_response"] = res.get('data')
                except Exception as e:
                    print(f"[VT] เกิดข้อผิดพลาดขณะดึง Report หลังอัปโหลด: {e}")
            else:
                print("[VT] ไม่สามารถอัปโหลดไฟล์ได้")
                results["vt_skipped"] = True

    os.makedirs("results", exist_ok=True)
    save_path = f"results/vt_{md5}.json"
    with open(save_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4)

    print(f"\n--- จบการทำงาน บันทึกผลลัพธ์ไว้ที่: {save_path} ---")
    
    # แสดงผลชนิดของมัลแวร์ที่สกัดได้
    if "extracted_malware_types" in results:
        print("\n=== 🦠 ชนิดมัลแวร์ที่ตรวจพบ ===")
        if results["extracted_malware_types"]:
            for m_type in results["extracted_malware_types"]:
                print(f"- {m_type}")
        else:
            print("✅ ไม่พบมัลแวร์ (ไฟล์สะอาด)")

    return {"success": True, "data": results}

if __name__ == "__main__":
    # เปลี่ยนชื่อไฟล์ตรงนี้ให้ตรงกับไฟล์ที่คุณมีในเครื่อง
    TEST_FILE_PATH = "./AnyDesk.exe" 
    result = run_virustotal_test(file_path=TEST_FILE_PATH)