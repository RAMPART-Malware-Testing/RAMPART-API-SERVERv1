import os
import json
import time
import hashlib
from dotenv import load_dotenv

# นำเข้าเฉพาะคลาส VirusTotal ของคุณ
from calling.VirusTotal import VirusTotal

load_dotenv()

VIRUSTOTAL_MAX_SIZE = 32 * 1024 * 1024

def calculate_hashes(file_path: str) -> dict:
    """
    1. อ่านไฟล์และคำนวณค่า MD5 และ SHA256 
    ใช้การอ่านแบบ chunk เพื่อไม่ให้กิน Memory หากไฟล์มีขนาดใหญ่
    """
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

    # วิเคราะห์ค่า hash และขนาดไฟล์
    file_hashes = calculate_hashes(file_path)
    md5 = file_hashes["md5"]
    sha256 = file_hashes["sha256"]
    total_size = os.path.getsize(file_path)

    print(f"[INFO] ขนาดไฟล์: {total_size} bytes")
    print(f"[INFO] MD5: {md5}")
    print(f"[INFO] SHA256: {sha256}")

    vt = VirusTotal()
    results = {}

    # 2. ตรวจสอบกับ VirusTotal ด้วย Hash
    print("\n[VT] กำลังตรวจสอบ Report จาก Hash...")
    rp = vt.get_report_by_hash(sha256)

    if rp.get('success'):
        print("[VT] พบ Report จาก Hash เรียบร้อยแล้ว ไม่ต้องอัปโหลดใหม่")
        results["virustotal"] = rp.get("data")
    else:
        print("[VT] ไม่พบ Report จาก Hash")

        # 3. กรณีไม่มี report: วิเคราะห์ไฟล์ใหม่ (อัปโหลด)
        if total_size > VIRUSTOTAL_MAX_SIZE:
            print(f"[VT] ข้ามการอัปโหลดเนื่องจากไฟล์ใหญ่เกินไป ({total_size} bytes)")
            results["vt_skipped"] = True
            results["message"] = "File too large to upload, and no hash report found."
        else:
            print("[VT] กำลังอัปโหลดไฟล์เพื่อวิเคราะห์...")
            res = vt.upload_file(file_path=file_path)
            
            if res.get("success"):
                try:
                    # ปกติ VirusTotal อาจจะใช้เวลาวิเคราะห์ไฟล์ใหม่สักพัก 
                    # ผมปรับเวลาตั้งต้นเป็น 15 วินาที เพื่อให้โอกาสได้ Report สูงขึ้นครับ
                    print("[VT] อัปโหลดสำเร็จ รอ 15 วินาทีเพื่อให้ VT ประมวลผล...")
                    time.sleep(15) 
                    
                    id_b64 = res['data']['data']['id']
                    print(f"[VT] กำลังดึงผลลัพธ์ด้วย ID: {id_b64}...")
                    
                    new_rp = vt.get_report_by_base64(id_b64)
                    if new_rp.get('success'):
                        print("[VT] ได้รับผลการวิเคราะห์จากการอัปโหลดเรียบร้อย")
                        results["virustotal"] = new_rp.get("data")
                    else:
                        print("[VT] ดึงผลลัพธ์ไม่ทัน (อาจต้องใช้เวลาประมวลผลนานกว่านี้)")
                        results["virustotal_upload_response"] = res.get('data')
                except Exception as e:
                    print(f"[VT] เกิดข้อผิดพลาดขณะดึง Report หลังอัปโหลด: {e}")
            else:
                print("[VT] ไม่สามารถอัปโหลดไฟล์ได้")
                results["vt_skipped"] = True

    # บันทึกผลลัพธ์ลง JSON (ทั้งกรณีดึงจาก Hash ได้ หรือต้องอัปโหลดใหม่)
    os.makedirs("results", exist_ok=True)
    save_path = f"results/vt_{md5}.json"
    with open(save_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4)

    print(f"\n--- จบการทำงาน บันทึกผลลัพธ์ไว้ที่: {save_path} ---")
    return {"success": True, "data": results}

# ==========================================
# บล็อกสำหรับรันทดสอบ
# ==========================================
if __name__ == "__main__":
    # 1. เปลี่ยนชื่อไฟล์ตรงนี้ให้ตรงกับไฟล์ที่คุณมีในเครื่อง
    TEST_FILE_PATH = "./AnyDesk.exe" 

    result = run_virustotal_test(file_path=TEST_FILE_PATH)