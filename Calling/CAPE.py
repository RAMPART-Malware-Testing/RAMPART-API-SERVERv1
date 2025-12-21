import os
import requests
import hashlib
import time
from typing import Optional, Dict, Any
from dotenv import load_dotenv
import json

load_dotenv()    


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

    def delete_taskID(self,task_id):
        requests.get(f"{self.base_url}/apiv2/tasks/delete/{task_id}")

    def create_file_task(
        self,
        file_path: str,
        machine: Optional[str] = None,
        is_pcap: bool = False,
    ) -> Dict[str, Any]:
        check_analy = self.cheack_analyer(file_path)
        # pretty_json = json.dumps(check_analy, indent=4, ensure_ascii=False)
        if len(check_analy) > 0:
            return {
                # "x":json.dumps(existing_task_id)
                "status": "exists",
                "task_id": check_analy[0],
                "message": f"File already analyzed. Task ID: {check_analy[0]["id"]}"
            }
        

        url = f"{self.base_url}/apiv2/tasks/create/file/"

        files = {'file': open(file_path, 'rb')}
        data = {}

        if machine:
            data['machine'] = machine

        if is_pcap:
            data['pcap'] = '1'

        try:
            response = requests.post(url, files=files, data=data)
            response.raise_for_status()
            result = response.json()

            return {
                "status": "created",
                "task_id": result.get("data", {}).get("task_ids", [None])[0] if result.get("data") else None,
                "response": result
            }
        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e)}
        finally:
            files['file'].close()

    def get_task_status(self, task_id: int) -> Dict[str, Any]:
        url = f"{self.base_url}/apiv2/tasks/status/{task_id}"
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}

    def wait_for_task(
        self,
        task_id: int,
        timeout: int = 600,
        poll_interval: int = 10,
        verbose: bool = True
    ) -> bool:
        start_time = time.time()

        while time.time() - start_time < timeout:
            status = self.get_task_status(task_id)

            if status.get("data"):
                task_status = status["data"].get("status")

                if verbose:
                    print(f"Task {task_id} status: {task_status}")

                if task_status == "reported":
                    return True
                elif task_status in ["failed_analysis", "failed_processing"]:
                    if verbose:
                        print(f"Task {task_id} failed!")
                    return False

            time.sleep(poll_interval)

        if verbose:
            print(f"Task {task_id} timeout after {timeout} seconds")
        return False

    def get_task_report(
        self,
        task_id: int,
        report_format: str = "json",
        download_zip: bool = False
    ):
        url = f"{self.base_url}/apiv2/tasks/get/report/{task_id}/{report_format}/"

        if download_zip:
            url += "zip/"

        try:
            response = requests.get(url)
            response.raise_for_status()

            if download_zip:
                return {"status": "success", "content": response.content, "type": "zip"}
            else:
                return {"status": "success", "data": response.json()}
        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e)}

    def get_report(self, task_id: int):
        report = self.get_task_report(task_id)

        if report.get("status") != "success":
            return report
        return None

        raw_data = report.get("data", {})
        
        signatures = []
        for sig in raw_data.get("signatures", []):
            signatures.append({
                "name": sig.get("name"),
                "description": sig.get("description"),
                "severity": sig.get("severity", 0)
            })

        network = raw_data.get("network", {})
        network_summary = {
            "hosts": network.get("hosts", [])[:5],
            "http_requests": [req.get("uri") for req in network.get("http", [])[:5]],
            "udp_count": len(network.get("udp", [])),
            "tcp_count": len(network.get("tcp", []))
        }

        target = raw_data.get("target", {})
        file_info = target.get("file", {})
        pe = file_info.get("pe",{})
        versioninfo = pe.get("versioninfo",{})

        summary = raw_data.get("summary", {})
        print(summary)

        company_name = "Unknown"
        for item in versioninfo:
            if item.get("name") == "CompanyName":
                company_name = item.get("value")

        filtered_data = {
            "malscore": raw_data.get("malscore"),
            "target_info": {
                "name": file_info.get("name"),
                "type": file_info.get("type"),
                "size": file_info.get("size"),
                "developer_company": company_name
            },
            "trust_info": {
                "is_signed": len(signatures) > 0,
                "signers": 0
            },
            "detected_signatures": signatures,
            "network_summary": network_summary,
            # "behavior_summary": {
            #     "files_written": summary.get("file_written", [])[:10],
            #     "registry_keys_modified": summary.get("regkey_written", [])[:10],
            #     "mutexes": summary.get("mutex", [])[:5]
            # }
        }

        print(filtered_data)

        return {
            "status": "success",
            "data": filtered_data,
            "defult":raw_data
        }

    def analyze_file_complete(
        self,
        file_path: str,
        machine: Optional[str] = None,
        is_pcap: bool = False,
        wait: bool = True,
        timeout: int = 600,
        get_filtered_report: bool = True
    ) -> Dict[str, Any]:
        # สร้าง task
        result = self.create_file_task(file_path, machine, is_pcap)

        if result.get("status") == "error":
            return result

        task_id = result.get("task_id")

        if not task_id:
            return {"status": "error", "error": "No task ID returned"}

        # ถ้าไม่รอ ก็ return task_id ไปเลย
        if not wait:
            return {"status": "submitted", "task_id": task_id}

        # รอให้วิเคราะห์เสร็จ
        print(f"Waiting for task {task_id} to complete...")
        success = self.wait_for_task(task_id, timeout=timeout)

        if not success:
            return {"status": "timeout", "task_id": task_id}

        # ดึงรายงาน
        if get_filtered_report:
            report = self.filter_report_for_llm(task_id)
        else:
            report = self.get_task_report(task_id)

        return {
            "status": "completed",
            "task_id": task_id,
            "report": report
        }


# ตัวอย่างการใช้งาน
# สร้าง instance
cape = CAPEAnalyzer()
file_path = "AnyDesk.exe"
# หรือถ้ามี API Token
# cape = CAPEAnalyzer(api_token="YOUR_TOKEN_HERE")

# ตัวอย่างที่ 1: เช็คว่าไฟล์เคยถูกวิเคราะห์แล้วหรือไม่
# print("=== 1: Check if file exists ===")
# task_id = cape.cheack_analyer(file_path)
# print(task_id)

# ตัวอย่างที่ 2: ส่งไฟล์เข้าวิเคราะห์
print('*'*100)
result = cape.create_file_task(file_path)
print(result)

# ตัวอย่างที่ 3: เช็คสถานะของ task
status_task = {
    "data":None,
    "error":False
}

task_id = result.get("task_id")
if task_id:
    status_task = cape.get_task_status(task_id.get("id"))
    print(f"Status: {status_task}")

# ตัวอย่างที่ 4: ดึงรายงานแบบ filtered สำหรับ LLM
print('*'*100)
if not status_task.get("error") and status_task.get("data"): 
    if task_id:
        report = cape.get_report(task_id.get("id"))
        print(f"Report: {report}")
        # with open("cape_report.json",'w',encoding="utf-8") as wf:
        #     report_str = json.dumps(report["defult"], ensure_ascii=False, indent=4)
        #     wf.write(report_str)
        #     wf.close()

# # ตัวอย่างที่ 5: วิเคราะห์ไฟล์แบบครบวงจร (แนะนำ!)
# print("\n=== Example 5: Complete analysis ===")
# full_result = cape.analyze_file_complete(
#     file_path="malware_sample.exe",
#     wait=True,
#     timeout=600,
#     get_filtered_report=True
# )
# print(f"Complete result: {full_result}")

# # ตัวอย่างที่ 6: วิเคราะห์ PCAP file
# print("\n=== Example 6: Analyze PCAP file ===")
# pcap_result = cape.analyze_file_complete(
#     file_path="network_traffic.pcap",
#     is_pcap=True,
#     wait=True
# )
# print(f"PCAP result: {pcap_result}")
