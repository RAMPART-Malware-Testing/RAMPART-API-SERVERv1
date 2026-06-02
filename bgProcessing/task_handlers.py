# task_handlers.py
from calling.VirusTotal import VirusToTalAPI
import json
from pathlib import Path

VIRUSTOTAL_MAX_SIZE = 32 * 1024 * 1024
vt = VirusToTalAPI()

def is_reportvt_complete(vt_data: dict) -> bool:
    if not vt_data:
        return False
    
    scan_summary = vt_data.get('scan_summary', {})
    total_scanners = scan_summary.get('total_scanners', 0)
    
    return total_scanners >= 10

def handle_virustotal(file_path: str, md5: str, total_size: int, is_retry: bool = False) -> dict:
    report = vt.get_report_by_hash(md5)
    
    if report.get('success'):
        vt_data = report.get('data')
        if is_reportvt_complete(vt_data):
            return {'success': True, 'data': vt_data}
        return {'success': False, 'retry': 60}
            
    if total_size > VIRUSTOTAL_MAX_SIZE:
        return {'success': False, 'message': 'File exceeds VT size limit', 'skip': True}
        
    if not is_retry:
         upload_res = vt.upload_file(file_path=file_path)
         if upload_res.get('success'):
             return {'success': False, 'retry': 300}
         return {'success': False, 'message': 'Upload failed', 'skip': True}
         
    return {'success': False, 'retry': 60}

def calculate_threat_scoreVT(json_path: str | Path) -> int:
    path = Path(json_path)
    
    # 1. ตรวจสอบและอ่านไฟล์ JSON
    if not path.exists():
        print(f"ไม่พบไฟล์รายงาน: {path}")
        return 0
        
    try:
        with open(path, 'r', encoding='utf-8') as file:
            vt_data = json.load(file)
    except Exception as e:
        print(f"เกิดข้อผิดพลาดในการอ่านไฟล์ JSON: {e}")
        return 0

    # 2. ดึงข้อมูลสำหรับคำนวณคะแนน
    scan_summary = vt_data.get('scan_summary', {})
    malicious = scan_summary.get('malicious_count', 0)
    total = scan_summary.get('total_scanners', 0)
    reputation = scan_summary.get('reputation', 0)
    
    sigma_rules = vt_data.get('security_analysis', {}).get('sigma_rules', {})
    sigma_critical = sigma_rules.get('critical', 0)
    sigma_high = sigma_rules.get('high', 0)

    # 3. คำนวณ Base Score (เต็ม 70) จากสัดส่วน AV
    base_score = min(((malicious / total) * 5) * 70, 70) if total > 0 else 0

    # 4. คำนวณ Extra Score (เต็ม 30) จากพฤติกรรมเสี่ยง
    extra_score = 0
    if sigma_critical > 0:
        extra_score += 20
    elif sigma_high > 0:
        extra_score += 10
        
    if reputation < 0:
        extra_score += min(abs(reputation) * 2, 10)

    final_score = int(min(base_score + extra_score, 100))
    
    # ถ้าสะอาดหมดจด ไม่มีสัญญาณอันตรายใดๆ ให้เป็น 0
    if malicious == 0 and sigma_critical == 0 and sigma_high == 0:
        return 0
        
    return final_score