import os
import requests
import hashlib
import time
from typing import Optional, Dict, Any
from dotenv import load_dotenv
import json

load_dotenv()    

from typing import Dict, Any, List, Optional
# ==========================================
# Helper Functions (ฟังก์ชันช่วยดึงข้อมูล)
# ==========================================

def extract_critical_apis(raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    ดึงข้อมูล API ที่มัลแวร์ชอบใช้ (DexClassLoader, Native Code) จาก android_api
    """
    critical_keys = [
        "api_dexloading",       # (สำคัญมาก) ใช้โหลดโค้ดอันตรายทีหลัง
        "api_native_code",      # ใช้ C/C++ ซ่อนพฤติกรรม
        "api_base64_decode",    # ใช้ถอดรหัส Payload ที่ซ่อนมา
        "api_sms_call",         # (Joker) ใช้สมัคร SMS กินเงิน
        "api_system_properties" # ใช้เช็คสภาพเครื่อง (Anti-VM)
    ]
    
    found_apis = []
    android_api = raw_data.get("android_api", {}) or {} # ใช้ or {} กันเหนียว
    
    for key in critical_keys:
        if key in android_api:
            data = android_api[key]
            # ดึงข้อมูลแค่พอสังเขป ลด Token
            desc = data.get("metadata", {}).get("description", key)
            file_count = len(data.get("files", {}))
            
            found_apis.append({
                "type": key,
                "description": desc,
                "file_count": file_count
            })
    return found_apis

def extract_high_risk_findings(raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    ดึงผลวิเคราะห์ Code Analysis เฉพาะระดับ High/Warning
    """
    findings = []
    code_analysis = raw_data.get("code_analysis", {})
    # code_analysis อาจเป็น Dict หรือ List ใน MobSF บางเวอร์ชัน ต้องเช็ค
    if not isinstance(code_analysis, dict):
        return []

    findings_data = code_analysis.get("findings", {})
    
    if not findings_data:
        return []

    for rule_id, data in findings_data.items():
        metadata = data.get("metadata", {})
        severity = metadata.get("severity", "info")
        
        # คัดเอาเฉพาะ High และ Warning
        if severity in ["high", "warning"]:
            findings.append({
                "rule_id": rule_id,
                "title": data.get("title", rule_id),
                "severity": severity
            })
    return findings

def clean_network_security(net_sec_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not net_sec_data:
        return None

    summary = net_sec_data.get("network_summary", {})
    findings = net_sec_data.get("network_findings", [])
    
    insecure_connections = []
    connected_domains = set()

    for item in findings:
        for scope in item.get("scope", []):
            connected_domains.add(scope)

        if item.get("severity") != "secure":
            insecure_connections.append({
                "severity": item.get("severity"),
                "scope": item.get("scope"),
                "description": item.get("description")
            })

    return {
        "summary": {
            "high": summary.get("high", 0),
            "warning": summary.get("warning", 0),
            "secure": summary.get("secure", 0)
        },
        "configured_domains": list(connected_domains),
        "vulnerabilities": insecure_connections
    }

def filter_playstore_details(playstore_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not playstore_data or playstore_data.get("error"):
        return None

    return {
        "title": playstore_data.get("title"),
        "developer": {
            "name": playstore_data.get("developer"),
            "id": playstore_data.get("developerId"),
            "website": playstore_data.get("developerWebsite"),
            "email": playstore_data.get("developerEmail")
        },
        "category": playstore_data.get("genre"),
        "description": playstore_data.get("summary") or (playstore_data.get("description", "")[:500] + "..."),
        "credibility": {
            "installs": playstore_data.get("installs"),
            "score": playstore_data.get("score"),
            "ratings_count": playstore_data.get("ratings"),
            "last_updated": playstore_data.get("lastUpdatedOn")
        }
    }

# ==========================================
# Main Function (ฟังก์ชันหลัก)
# ==========================================

def clean_mobsf_report(raw_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not raw_data:
        return None
    
    # 1. โครงสร้างพื้นฐาน + [NEW] Code Behavior
    cleaned = {
        "file_info": {
            "app_name": raw_data.get("app_name"),
            "package_name": raw_data.get("package_name"),
            "version_name": raw_data.get("version_name"),
            "size": raw_data.get("size"),
            "md5": raw_data.get("md5")
        },
        "security_score": raw_data.get("appsec", {}).get("security_score"),
        
        # --- ส่วนใหม่ที่เพิ่มเข้ามา ---
        "code_behavior": {
            "suspicious_apis": extract_critical_apis(raw_data),      # เช็ค DexLoading, NativeCode
            "risk_findings": extract_high_risk_findings(raw_data)    # เช็ค High Risk Findings
        },
        # ------------------------
        
        "signer_info": {},          
        "permissions": [],          
        "dangerous_services": [],   
        "suspicious_api_calls": [], 
        "high_risk_components": [], 
        
        "store_info": filter_playstore_details(raw_data.get("playstore_details")),
        "network_security": clean_network_security(raw_data.get("network_security"))
    }

    # 2. Signer Analysis
    cert_analysis = raw_data.get("certificate_analysis", {})
    cert_details = cert_analysis.get("certificate_info", "")
    
    cleaned["signer_info"] = {
        "raw_data": str(cert_details)[:500],
        "is_debug_cert": "debug" in str(cert_details).lower() or "android" in str(cert_details).lower(),
        "bad_certificate": cert_analysis.get("certificate_status") == "bad"
    }

    # 3. Permission Analysis
    if "permissions" in raw_data:
        for perm_name, details in raw_data["permissions"].items():
            is_dangerous = details.get("status") == "dangerous"
            is_malware_related = "SYSTEM_ALERT_WINDOW" in perm_name or "RECEIVE_SMS" in perm_name
            
            if is_dangerous or is_malware_related:
                cleaned["permissions"].append({
                    "name": perm_name,
                    "description": details.get("description")
                })

    # 4. Manifest Analysis
    manifest = raw_data.get("manifest_analysis", [])
    for item in manifest:
        title = ""
        desc = ""
        
        if isinstance(item, dict):
            title = str(item.get("title", "")).lower()
            desc = str(item.get("desc", "")).lower()
        elif isinstance(item, str):
            title = str(item).lower()
            desc = ""
        else:
            continue
        
        if "accessibility" in title or "accessibility" in desc:
            cleaned["dangerous_services"].append("BIND_ACCESSIBILITY_SERVICE")
        if "device admin" in title:
            cleaned["dangerous_services"].append("BIND_DEVICE_ADMIN")

    # 5. Code Analysis (Legacy - เก็บไว้ตามคำขอเพื่อความชัวร์)
    code_analysis = raw_data.get("code_analysis", {})
    target_apis = ["DexClassLoader", "PathClassLoader", "Runtime.exec", "Cipher"]
    
    # เช็คว่า code_analysis เป็น dict จริงๆ ก่อน loop
    if isinstance(code_analysis, dict):
        for key, findings in code_analysis.items():
            key_str = str(key)
            
            if any(api in key_str for api in target_apis):
                cleaned["suspicious_api_calls"].append(key_str)
                
            elif isinstance(findings, dict) and findings.get("metadata", {}).get("severity") == "high":
                cleaned["high_risk_components"].append(key_str)

    return cleaned

rf = open("Calling\z-report2.0-cape-34.json",'r',encoding='utf-8')
rf_data = json.load(rf)
rf.close()

print(rf_data.get("data"))
print(clean_mobsf_report(rf_data.get("data")))


class CAPEAnalyzer:
    def __init__(self):
        self.base_url = os.getenv("CAPE_BASE_URL")
        if not self.base_url:
            raise ValueError("CAPE_BASE_URL not found in .env file")

    def calculate_hash(self, file_path: str, hash_type: str = "sha256") -> str:
        hash_obj = hashlib.new(hash_type)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

    def cheack_analyer(self, file_path: str, hash_type: str = "sha256"):
        file_hash = self.calculate_hash(file_path, hash_type)
        url = f"{self.base_url}/apiv2/tasks/search/{hash_type}/{file_hash}/"
        try:
            response = requests.get(url)
            js = response.json()
            return js.get("data")
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}

    def delete_taskID(self, task_id):
        try:
            requests.get(f"{self.base_url}/apiv2/tasks/delete/{task_id}")
        except: pass

    def create_file_task(self, file_path: str, machine: Optional[str] = None, is_pcap: bool = False) -> Dict[str, Any]:
        check_analy = self.cheack_analyer(file_path)
        if check_analy and len(check_analy) > 0:
            return {
                "status": "exists",
                "task_id": check_analy[0].get('id'),
                "message": "File already analyzed."
            }
        
        url = f"{self.base_url}/apiv2/tasks/create/file/"
        files = {'file': open(file_path, 'rb')}
        data = {}
        if machine: data['machine'] = machine
        if is_pcap: data['pcap'] = '1'

        try:
            response = requests.post(url, files=files, data=data)
            response.raise_for_status()
            result = response.json()
            return {
                "status": "created",
                "task_id": result.get("data", {}).get("task_ids", [None])[0] if result.get("data") else None,
                "response": result
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}
        finally:
            files['file'].close()

    def get_task_status(self, task_id: int) -> Dict[str, Any]:
        url = f"{self.base_url}/apiv2/tasks/status/{task_id}"
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e), "data": None}

    def get_task_report(self, task_id: int, report_format: str = "json"):
        url = f"{self.base_url}/apiv2/tasks/get/report/{task_id}/{report_format}/"
        try:
            response = requests.get(url)
            response.raise_for_status()
            return {"status": "success", "data": response.json()}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def get_report(self, task_id: int):
        report = self.get_task_report(task_id)
        
        with open(f'z-report2.0-cape-{task_id}.json','w',encoding='utf-8') as wf:
            wf.write(json.dumps(report, ensure_ascii=False, indent=4))

        if report.get("status") != "success": return report
        return {"status": "success", "data": clean_mobsf_report(report.get("data", {}))}

# (ลบ Method MobSF ที่หลุดเข้ามา: scan_file, get_report_json)
# (ลบ Test Code ท้ายไฟล์)