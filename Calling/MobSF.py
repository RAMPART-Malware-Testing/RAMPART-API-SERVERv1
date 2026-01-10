import os
import requests
from dotenv import load_dotenv
import json
from requests.exceptions import ReadTimeout
from typing import Dict, Any, List, Optional

load_dotenv()

# ==========================================
# Helper Functions (ฟังก์ชันช่วยดึงข้อมูล)
# ==========================================
# ... (คงเดิม: extract_critical_apis, extract_high_risk_findings, etc.) ...
# เพื่อประหยัดพื้นที่ ผมขอละ Helper Functions ไว้เหมือนเดิมนะครับ 
# เพราะ Logic ส่วนนี้ถูกต้องแล้ว

def extract_critical_apis(raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    critical_keys = ["api_dexloading", "api_native_code", "api_base64_decode", "api_sms_call", "api_system_properties"]
    found_apis = []
    android_api = raw_data.get("android_api", {}) or {}
    for key in critical_keys:
        if key in android_api:
            data = android_api[key]
            desc = data.get("metadata", {}).get("description", key)
            file_count = len(data.get("files", {}))
            found_apis.append({"type": key, "description": desc, "file_count": file_count})
    return found_apis

def extract_high_risk_findings(raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    code_analysis = raw_data.get("code_analysis", {})
    if not isinstance(code_analysis, dict): return []
    findings_data = code_analysis.get("findings", {})
    if not findings_data: return []
    for rule_id, data in findings_data.items():
        metadata = data.get("metadata", {})
        severity = metadata.get("severity", "info")
        if severity in ["high", "warning"]:
            findings.append({"rule_id": rule_id, "title": data.get("title", rule_id), "severity": severity})
    return findings

def clean_network_security(net_sec_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not net_sec_data: return None
    summary = net_sec_data.get("network_summary", {})
    findings = net_sec_data.get("network_findings", [])
    insecure_connections = []
    connected_domains = set()
    for item in findings:
        for scope in item.get("scope", []): connected_domains.add(scope)
        if item.get("severity") != "secure":
            insecure_connections.append({"severity": item.get("severity"), "scope": item.get("scope"), "description": item.get("description")})
    return {
        "summary": {"high": summary.get("high", 0), "warning": summary.get("warning", 0), "secure": summary.get("secure", 0)},
        "configured_domains": list(connected_domains),
        "vulnerabilities": insecure_connections
    }

def filter_playstore_details(playstore_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not playstore_data or playstore_data.get("error"): return None
    return {
        "title": playstore_data.get("title"),
        "developer": {"name": playstore_data.get("developer"), "id": playstore_data.get("developerId"), "website": playstore_data.get("developerWebsite"), "email": playstore_data.get("developerEmail")},
        "category": playstore_data.get("genre"),
        "description": playstore_data.get("summary") or (playstore_data.get("description", "")[:500] + "..."),
        "credibility": {"installs": playstore_data.get("installs"), "score": playstore_data.get("score"), "ratings_count": playstore_data.get("ratings"), "last_updated": playstore_data.get("lastUpdatedOn")}
    }

def clean_mobsf_report(raw_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not raw_data: return None
    cleaned = {
        "file_info": {
            "app_name": raw_data.get("app_name"),
            "package_name": raw_data.get("package_name"),
            "version_name": raw_data.get("version_name"),
            "size": raw_data.get("size"),
            "md5": raw_data.get("md5")
        },
        "security_score": raw_data.get("appsec", {}).get("security_score"),
        "code_behavior": {
            "suspicious_apis": extract_critical_apis(raw_data),
            "risk_findings": extract_high_risk_findings(raw_data)
        },
        "signer_info": {}, "permissions": [], "dangerous_services": [], "suspicious_api_calls": [], "high_risk_components": [],
        "store_info": filter_playstore_details(raw_data.get("playstore_details")),
        "network_security": clean_network_security(raw_data.get("network_security"))
    }
    cert_analysis = raw_data.get("certificate_analysis", {})
    cert_details = cert_analysis.get("certificate_info", "")
    cleaned["signer_info"] = {
        "raw_data": str(cert_details)[:500],
        "is_debug_cert": "debug" in str(cert_details).lower() or "android" in str(cert_details).lower(),
        "bad_certificate": cert_analysis.get("certificate_status") == "bad"
    }
    if "permissions" in raw_data:
        for perm_name, details in raw_data["permissions"].items():
            is_dangerous = details.get("status") == "dangerous"
            is_malware_related = "SYSTEM_ALERT_WINDOW" in perm_name or "RECEIVE_SMS" in perm_name
            if is_dangerous or is_malware_related:
                cleaned["permissions"].append({"name": perm_name, "description": details.get("description")})
    manifest = raw_data.get("manifest_analysis", [])
    for item in manifest:
        title = str(item.get("title", "")).lower() if isinstance(item, dict) else str(item).lower()
        if "accessibility" in title: cleaned["dangerous_services"].append("BIND_ACCESSIBILITY_SERVICE")
        if "device admin" in title: cleaned["dangerous_services"].append("BIND_DEVICE_ADMIN")
    code_analysis = raw_data.get("code_analysis", {})
    target_apis = ["DexClassLoader", "PathClassLoader", "Runtime.exec", "Cipher"]
    if isinstance(code_analysis, dict):
        for key, findings in code_analysis.items():
            key_str = str(key)
            if any(api in key_str for api in target_apis): cleaned["suspicious_api_calls"].append(key_str)
            elif isinstance(findings, dict) and findings.get("metadata", {}).get("severity") == "high": cleaned["high_risk_components"].append(key_str)
    return cleaned

# ==========================================
# Main Class
# ==========================================

class MobSFCall:
    def __init__(self):
        self.api_key = os.getenv("MOB_API_KEY")
        self.base_url = os.getenv("MOBSF_BASE_URL", "http://localhost:8001")

    def _get_headers(self):
        return {"Authorization": self.api_key}

    def upload_file(self, file_path, original_filename=None):
        if not os.path.exists(file_path): return {"success": False, "error": f"File not found: {file_path}"}
        url = f"{self.base_url}/api/v1/upload"
        filename = original_filename if original_filename else os.path.basename(file_path)
        try:
            with open(file_path, 'rb') as file:
                files = {'file': (filename, file, 'application/octet-stream')}
                response = requests.post(url, headers=self._get_headers(), files=files)
            if response.status_code == 200: return {"success": True, "data": response.json()}
            elif response.status_code == 401: return {"success": False, "error": "Unauthorized"}
            else: return {"success": False, "error": f"Error {response.status_code}: {response.text}"}
        except Exception as e: return {"success": False, "error": str(e)}

    def scan_uploaded_file(self, file_hash, timeout=None):
        """
        สั่ง Scan ไฟล์ตาม Hash
        timeout: ถ้าใส่มา จะทำการตัด connection เมื่อครบเวลา (Fire-and-Forget)
        """
        url = f"{self.base_url}/api/v1/scan"
        data = {'hash': file_hash}
        try:
            requests.post(url, headers=self._get_headers(), data=data, timeout=timeout)
            # ถ้าตอบกลับทันเวลา (ไฟล์เล็ก)
            return {"success": True, "data": "scan_started_finished"}
        except ReadTimeout:
            # *** HERO LOGIC *** ตัดสายแล้วบอกว่าสำเร็จ (Background Processing)
            print(f"[MobSF] Scan triggered successfully (Background Mode).")
            return {"success": True, "data": "scan_started_background"}
        except Exception as e:
            return {"success": False, "error": f"Request failed: {str(e)}"}

    def generate_json_report(self, file_hash):
        url = f"{self.base_url}/api/v1/report_json"
        data = {'hash': file_hash}
        try:
            response = requests.post(url, headers=self._get_headers(), data=data)
            if response.status_code == 200:
                raw = response.json()
                with open(f'z-report2.0-mob.json', 'w', encoding='utf-8') as f: json.dump(raw, f)
                return {"success": True, "data": clean_mobsf_report(raw)}
            else:
                return {"success": False, "error": "Report not ready"}
        except Exception as e:
            return {"success": False, "error": str(e)}

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