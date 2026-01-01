import os
import requests
from dotenv import load_dotenv
import time 
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

class MobSFCall:
    def __init__(self):
        self.api_key = os.getenv("MOB_API_KEY")
        self.base_url = os.getenv("MOBSF_BASE_URL", "http://localhost:8000")

    def _get_headers(self):
        return {
            "Authorization": self.api_key
        }

    def upload_file(self, file_path, original_filename=None):
        if not os.path.exists(file_path):
            return {"success": False, "error": f"File not found: {file_path}"}

        url = f"{self.base_url}/api/v1/upload"
        headers = self._get_headers()

        filename = original_filename if original_filename else os.path.basename(file_path)
        try:
            with open(file_path, 'rb') as file:
                files = {'file': (filename, file, 'application/octet-stream')}
                response = requests.post(url, headers=headers, files=files)

            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            elif response.status_code == 401:
                return {"success": False, "error": "Unauthorized: Invalid API key"}
            else:
                error_msg = response.json().get('error', 'Unknown error')
                return {"success": False, "error": f"Error {response.status_code}: {error_msg}"}

        except requests.exceptions.RequestException as e:
            return {"success": False, "error": f"Request failed: {str(e)}"}

    def scan_uploaded_file(self, file_hash):
        url = f"{self.base_url}/api/v1/scan"
        headers = self._get_headers()
        data = {'hash': file_hash}

        try:
            response = requests.post(url, headers=headers, data=data)
            raw = response.json()
            with open('z-report2.0-mob.json','w',encoding='utf-8') as wf:
                wf.write(json.dumps(raw, ensure_ascii=False, indent=4))
                wf.close()

            if response.status_code == 200:
                return {"success": True, "data": raw}
            elif response.status_code == 401:
                return {"success": False, "error": "Unauthorized: Invalid API key"}
            else:
                error_msg = raw.get('error', 'Unknown error')
                return {"success": False, "error": f"Error {response.status_code}: {error_msg}"}

        except requests.exceptions.RequestException as e:
            return {"success": False, "error": f"Request failed: {str(e)}"}

    def generate_json_report(self, file_hash):
        url = f"{self.base_url}/api/v1/report_json"
        headers = self._get_headers()
        data = {'hash': file_hash}

        try:
            response = requests.post(url, headers=headers, data=data)
            raw = response.json()
            print(response.status_code)
            if response.status_code == 200:
                with open('z-report2.1-mob.json','w',encoding='utf-8') as wf:
                    wf.write(json.dumps(raw, ensure_ascii=False, indent=4))
                    wf.close()
                res = clean_mobsf_report(raw)
                return {"success": True, "data": res}
            elif response.status_code == 401:
                return {"success": False, "error": "Unauthorized: Invalid API key"}
            else:
                error_msg = raw.get('error', 'Unknown error')
                return {"success": False, "error": f"Error {response.status_code}: {error_msg}"}

        except requests.exceptions.RequestException as e:
            return {"success": False, "error": f"Request failed: {str(e)}"}
    
    def search(self, file_hash):
        url = f"{self.base_url}/api/v1/search"
        headers = self._get_headers()
        data = {'query': file_hash}

        try:
            response = requests.post(url, headers=headers, data=data)
            if response.status_code == 200:
                res = clean_mobsf_report(response.json())
                return {"success": True, "data": res}
            elif response.status_code == 401:
                return {"success": False, "error": "Unauthorized: Invalid API key"}
            else:
                error_msg = response.json().get('error', 'Unknown error')
                return {"success": False, "error": f"Error {response.status_code}: {error_msg}"}

        except requests.exceptions.RequestException as e:
            return {"success": False, "error": f"Request failed: {str(e)}"}
    
    def scan_logs(self, file_hash):
        url = f"{self.base_url}/api/v1/scan_logs"
        headers = self._get_headers()
        data = {'hash': file_hash}

        try:
            response = requests.post(url, headers=headers, data=data)
            if response.status_code == 200:
                res = clean_mobsf_report(response.json())
                return {"success": True, "data": res}
            elif response.status_code == 401:
                return {"success": False, "error": "Unauthorized: Invalid API key"}
            else:
                error_msg = response.json().get('error', 'Unknown error')
                return {"success": False, "error": f"Error {response.status_code}: {error_msg}"}

        except requests.exceptions.RequestException as e:
            return {"success": False, "error": f"Request failed: {str(e)}"}
    
    def tasks(self):
        url = f"{self.base_url}/api/v1/tasks"
        headers = self._get_headers()

        try:
            response = requests.post(url, headers=headers)
            if response.status_code == 200:
                res = clean_mobsf_report(response.json())
                return {"success": True, "data": res}
            elif response.status_code == 401:
                return {"success": False, "error": "Unauthorized: Invalid API key"}
            else:
                error_msg = response.json().get('error', 'Unknown error')
                return {"success": False, "error": f"Error {response.status_code}: {error_msg}"}

        except requests.exceptions.RequestException as e:
            return {"success": False, "error": f"Request failed: {str(e)}"}
    
    def scorecard(self,file_hash):
        url = f"{self.base_url}/api/v1/scorecard"
        headers = self._get_headers()
        data = {'hash': file_hash}

        try:
            response = requests.post(url, headers=headers, data=data)
            if response.status_code == 200:
                res = clean_mobsf_report(response.json())
                return {"success": True, "data": res}
            elif response.status_code == 401:
                return {"success": False, "error": "Unauthorized: Invalid API key"}
            else:
                error_msg = response.json().get('error', 'Unknown error')
                return {"success": False, "error": f"Error {response.status_code}: {error_msg}"}

        except requests.exceptions.RequestException as e:
            return {"success": False, "error": f"Request failed: {str(e)}"}
    
    def delete_scan(self,file_hash):
        url = f"{self.base_url}/api/v1/delete_scan"
        headers = self._get_headers()
        data = {'hash': file_hash}

        try:
            response = requests.post(url, headers=headers, data=data)
            if response.status_code == 200:
                res = clean_mobsf_report(response.json())
                return {"success": True, "data": res}
            elif response.status_code == 401:
                return {"success": False, "error": "Unauthorized: Invalid API key"}
            else:
                error_msg = response.json().get('error', 'Unknown error')
                return {"success": False, "error": f"Error {response.status_code}: {error_msg}"}

        except requests.exceptions.RequestException as e:
            return {"success": False, "error": f"Request failed: {str(e)}"}

    def scan_file(self, file_path):
        print(f"MobSF Uploading file: {file_path}")
        upload_result = self.upload_file(file_path)
        if not upload_result['success']:
            print(f"MobSF File upload failed: {upload_result['error']}")
            return upload_result

        file_hash = upload_result['data'].get('hash', '')
        if not file_hash:
            print(f"MobSF File upload did not return a hash.")
            return {"success": False, "error": "No file hash returned after upload."}
        print(f"MobSF File uploaded successfully. Hash: {file_hash}")

        print(f"MobSF scanning file!")
        s = self.scan_uploaded_file(file_hash)
        if not s["success"]:
            print(f"MobSF File scan failed: {str(upload_result)}")
            return upload_result
        
        print(f"MobSF Scan completed!")
        return clean_mobsf_report(s["data"])

        print(f"MobSF Generating JSON report...")
        # time.sleep(10)
        # report = self.generate_json_report(file_hash)
        # if not report['success']:
        #     print(f"MobSF Report generation failed: {report['error']}")
        #     return report

        print(f"MobSF Report generated successfully!")
        # return report

mob = None
def MobSF():
    global mob
    if mob is None:
        mob = MobSFCall()
    return mob

# import json

# m = MobSF()
# up = m.upload_file("C:/Users/ubuntu24/Downloads/AntiDot/bc02322aaf96fa1841101636dc4c8011da3bcc5571a6f0278813884ce54b5b3f.apk")
# print(json.dumps(up, indent=4))
# hash = "1c9e4bb8da3ece689dc6cc7eadf25494"
# print("=====================================")
# s = m.scan_uploaded_file(hash)
# print(s["success"])
# print(json.dumps(s, indent=4))
# print("=====================================")
# sl = m.scan_logs(hash)
# print(json.dumps(sl, indent=4))
# print("=====================================")
# ss = m.search(hash)
# print(json.dumps(ss, indent=4))
# print("=====================================")
# t = m.tasks()
# print(json.dumps(t, indent=4))
# print("=====================================")
# sc = m.scorecard(hash)
# print(json.dumps(sc, indent=4))
# print("=====================================")
# ds = m.delete_scan(hash)
# print(json.dumps(ds, indent=4))

# with open('z-report3-result.json','r',encoding='utf-8') as rf:
#     raw = json.loads(rf.read())
#     cleaned = clean_mobsf_report(raw["mobsf"])
#     raw["mobsf"] = cleaned
#     with open('z-report3-result.json','w',encoding='utf-8') as wf:
#         wf.write(json.dumps(raw,ensure_ascii=False, indent=4))
#         wf.close()
#     rf.close()
    # with open('z-report3-cleaned-mobsf.json','w',encoding='utf-8') as wf:
    #     wf.write(json.dumps(cleaned,ensure_ascii=False, indent=4))
    #     wf.close()

