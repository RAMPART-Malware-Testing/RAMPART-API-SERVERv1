# task_handlers.py
from calling.VirusTotal import VirusToTalAPI

VIRUSTOTAL_MAX_SIZE = 32 * 1024 * 1024
vt = VirusToTalAPI()

def is_report_complete(vt_data: dict) -> bool:
    if not vt_data:
        return False
    
    scan_summary = vt_data.get('virustotal', {}).get('scan_summary', {})
    total_scanners = scan_summary.get('total_scanners', 0)
    
    return total_scanners >= 10

def handle_virustotal(file_path: str, md5: str, total_size: int, is_retry: bool = False) -> dict:
    report = vt.get_report_by_hash(md5)
    
    if report.get('success'):
        vt_data = report.get('data')
        if is_report_complete(vt_data):
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