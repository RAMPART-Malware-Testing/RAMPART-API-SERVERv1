import os
import requests
from dotenv import load_dotenv
import base64
import hashlib
from typing import Dict, Any, List, Optional
import json

def deCode_base64_string(b64_string: str) -> str:
    b64_bytes = b64_string.encode("utf-8")
    decoded_bytes = base64.b64decode(b64_bytes)
    decoded_text = decoded_bytes.decode("utf-8")
    return decoded_text


class VirusToTalAPI:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        load_dotenv()

        self.api_keys = self._load_api_keys()
        if not self.api_keys:
            raise ValueError("No VirusTotal API keys found in environment variables.")

        self.current_key_index = 0
        self.session = requests.Session()
        self._update_session_headers()

    def _load_api_keys(self) -> List[str]:
        keys = []

        index = 1
        while True:
            key = os.getenv(f'VIRUSTOTAL_KEY{index}')
            if key:
                keys.append(key)
                index += 1
            else:
                break

        if not keys:
            single_key = os.getenv('VIRUSTOTAL_API_KEY')
            if single_key:
                keys.append(single_key)

        return keys

    def _update_session_headers(self):
        current_key = self.api_keys[self.current_key_index]
        self.session.headers.update({
            "x-apikey": current_key,
            "accept": "application/json"
        })

    def _switch_api_key(self) -> bool:
        if self.current_key_index < len(self.api_keys) - 1:
            self.current_key_index += 1
            self._update_session_headers()
            return True
        else:
            return False

    def _reset_key_index(self):
        self.current_key_index = 0
        self._update_session_headers()

    def _make_request(self, method: str, url: str, max_retries: Optional[int] = None, **kwargs) -> Dict[str, Any]:
        if max_retries is None:
            max_retries = len(self.api_keys)

        last_error = None

        for _ in range(max_retries):
            try:
                response = self.session.request(method, url, **kwargs)
                response.raise_for_status()
                if self.current_key_index > 0:
                    self._reset_key_index()
                return response.json()

            except requests.exceptions.HTTPError as e:
                status_code = e.response.status_code if e.response else None

                if status_code in [429, 403]:
                    if not self._switch_api_key():
                        last_error = e
                        break
                    continue
                else:
                    raise RuntimeError(f"HTTP Error {status_code}: {e}")

            except requests.exceptions.RequestException as e:
                last_error = e

                if not self._switch_api_key():
                    break
                continue

        self._reset_key_index()
        raise RuntimeError(f"All API keys failed. Last error: {last_error}")

    # -----------------------------
    # Upload File and Scan
    # -----------------------------
    def upload_file(self, file_path: str) -> Dict[str, Any]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        url = f"{self.BASE_URL}/files"

        try:
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                return self._make_request("POST", url, files=files)

        except Exception as e:
            raise RuntimeError(f"Error uploading file to VirusTotal: {e}")

    # -----------------------------
    # Clean VirusTotal Report
    # -----------------------------
    def _clean_virustotal_report(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        if not raw_data:
            return None

        # Extract attributes
        attrs = raw_data.get("data", {}).get("attributes", {})

        # Detect file type
        file_type = attrs.get("type_description", "")
        type_tags = attrs.get("type_tags", [])
        is_android = "androguard" in attrs or "apk" in type_tags or "android" in type_tags
        is_windows = "peexe" in type_tags or "pe" in type_tags or "Win" in file_type

        # 1. Extract identity information (CRITICAL)
        developer_signer = None
        package_name = None
        permissions = []

        if is_android:
            # Android APK - use androguard
            androguard = attrs.get("androguard", {})
            cert = androguard.get("certificate", {}).get("Subject", {})
            developer_signer = cert.get("O")  # Organization
            package_name = androguard.get("Package")

            # Extract permissions (just names, not descriptions)
            perms_raw = androguard.get("permission_details", {})
            permissions = list(perms_raw.keys()) if perms_raw else []

        elif is_windows:
            # Windows PE - use signature_info
            sig_info = attrs.get("signature_info", {})
            signers = sig_info.get("signers", "")

            # Extract first signer (usually the actual developer)
            if signers:
                developer_signer = signers.split(";")[0].strip()

            # Product name as identifier
            package_name = sig_info.get("product", attrs.get("meaningful_name"))

        # 2. Extract security statistics
        stats = attrs.get("last_analysis_stats", {})

        # 3. Extract only MALICIOUS and SUSPICIOUS findings (not the 60+ safe ones)
        malware_findings = []
        suspicious_findings = []
        results = attrs.get("last_analysis_results", {})

        for engine, result in results.items():
            category = result.get("category")
            if category == "malicious":
                malware_findings.append(f"{engine}: {result.get('result')}")
            elif category == "suspicious":
                suspicious_findings.append(f"{engine}: {result.get('result')}")

        # 4. Extract file hashes
        file_hashes = {
            "md5": attrs.get("md5"),
            "sha1": attrs.get("sha1"),
            "sha256": attrs.get("sha256")
        }

        # 5. Extract reputation and votes
        reputation = attrs.get("reputation", 0)
        total_votes = attrs.get("total_votes", {})

        # 6. Extract sigma analysis (security rules)
        sigma_stats = attrs.get("sigma_analysis_stats", {})

        # 7. Extract sandbox verdicts
        sandbox_verdicts = attrs.get("sandbox_verdicts", {})
        sandbox_summary = []
        for sandbox_name, verdict in sandbox_verdicts.items():
            sandbox_summary.append({
                "sandbox": sandbox_name,
                "category": verdict.get("category"),
                "malware_classification": verdict.get("malware_classification", [])
            })

        return {
            "file_info": {
                "names": attrs.get("names", [])[:3],  # First 3 names only
                "meaningful_name": attrs.get("meaningful_name"),
                "type": file_type,
                "size": attrs.get("size"),
                "hashes": file_hashes
            },
            "app_identity": {
                "package_name": package_name,
                "developer_signer": developer_signer,  # Critical for authenticity check
                "is_verified": attrs.get("signature_info", {}).get("verified") == "Signed" if is_windows else None,
                "is_trusted_developer": any(trusted in str(developer_signer).lower()
                                           for trusted in ["google", "microsoft", "apple"]) if developer_signer else False
            },
            "scan_summary": {
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "undetected_count": stats.get("undetected", 0),
                "harmless_count": stats.get("harmless", 0),
                "total_scanners": sum(stats.values()) if stats else 0,
                "reputation": reputation,
                "community_votes": {
                    "harmless": total_votes.get("harmless", 0),
                    "malicious": total_votes.get("malicious", 0)
                }
            },
            "threats_found": {
                "malicious": malware_findings,  # Critical threats
                "suspicious": suspicious_findings  # Potential threats
            },
            "security_analysis": {
                "sigma_rules": sigma_stats,  # High/Medium/Low security rules triggered
                "sandbox_results": sandbox_summary  # Sandbox execution results
            },
            "permissions": permissions,  # Android permissions only
            "tags": attrs.get("tags", [])[:10]  # First 10 tags for behavior indicators
        }

    # -----------------------------
    # Get Report by File Hash
    # -----------------------------
    def get_report(self, base64_string: str, clean: bool = True) -> Dict[str, Any]:
        md5_and_number = deCode_base64_string(base64_string)
        file_hash = md5_and_number.split(':')[0]
        url = f"{self.BASE_URL}/files/{file_hash}"

        try:
            raw_report = self._make_request("GET", url)
            return self._clean_virustotal_report(raw_report) if clean else raw_report
        except Exception as e:
            raise RuntimeError(f"Error fetching report: {e}")

    def get_report_by_hash(self, file_hash: str, clean: bool = True) -> Dict[str, Any]:
        url = f"{self.BASE_URL}/files/{file_hash}"

        try:
            raw_report = self._make_request("GET", url)
            return self._clean_virustotal_report(raw_report) if clean else raw_report
        except Exception as e:
            raise RuntimeError(f"Error fetching report for hash {file_hash}: {e}")

virustotal = None

def VirusTotal():
    global virustotal
    if virustotal is None:
        virustotal = VirusToTalAPI()
        return virustotal
    return virustotal


# x = VirusTotal().upload_file("AnyDesk.exe")
# print(x["data"]['id'])
# y = VirusTotal().get_report(x["data"]['id'])
# print(y)

