import os
import requests
import hashlib
import time
from typing import Optional, Dict, Any
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class CAPEAnalyzer:
    """
    CAPE Sandbox API Wrapper
    ใช้สำหรับจัดการ API ทั้ง 4 ตัว:
    1. File Create - ส่งไฟล์เข้าวิเคราะห์
    2. Basic Task Search - เช็ค Hash ก่อนส่ง
    3. Task Status - ตรวจสอบสถานะการวิเคราะห์
    4. Task Report - ดึงรายงานผลการวิเคราะห์
    """

    def __init__(self, base_url: Optional[str] = None, api_token: Optional[str] = None):
        """
        Initialize CAPE Analyzer

        Args:
            base_url: CAPE base URL (default: จาก .env CAOE_BASE_URL)
            api_token: API Token สำหรับ authentication (optional)
        """
        self.base_url = base_url or os.getenv("CAOE_BASE_URL")
        self.api_token = api_token

        if not self.base_url:
            raise ValueError("CAOE_BASE_URL not found in .env file")

        # Remove trailing slash
        self.base_url = self.base_url.rstrip('/')

        # Setup headers
        self.headers = {}
        if self.api_token:
            self.headers["Authorization"] = f"Token {self.api_token}"

    def _calculate_hash(self, file_path: str, hash_type: str = "sha256") -> str:
        """
        คำนวณ hash ของไฟล์

        Args:
            file_path: path ของไฟล์
            hash_type: ประเภท hash (md5, sha1, sha256)

        Returns:
            hash string
        """
        hash_obj = hashlib.new(hash_type)

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)

        return hash_obj.hexdigest()

    def search_by_hash(self, file_hash: str, hash_type: str = "sha256") -> Dict[str, Any]:
        """
        2. Basic Task Search - เช็ค Hash ของไฟล์ก่อนส่ง

        Args:
            file_hash: hash ของไฟล์
            hash_type: ประเภท hash (md5, sha1, sha256)

        Returns:
            ผลการค้นหา task ที่มี hash นี้
        """
        url = f"{self.base_url}/apiv2/tasks/search/{hash_type}/{file_hash}/"

        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}

    def check_file_exists(self, file_path: str, hash_type: str = "sha256") -> Optional[int]:
        """
        เช็คว่าไฟล์เคยถูกวิเคราะห์แล้วหรือไม่

        Args:
            file_path: path ของไฟล์
            hash_type: ประเภท hash ที่จะใช้เช็ค

        Returns:
            task_id ถ้าเจอ, None ถ้าไม่เจอ
        """
        file_hash = self._calculate_hash(file_path, hash_type)
        result = self.search_by_hash(file_hash, hash_type)

        if result.get("data") and len(result["data"]) > 0:
            # Return the most recent task ID
            return result["data"][0].get("id")

        return None

    def create_file_task(
        self,
        file_path: str,
        machine: Optional[str] = None,
        is_pcap: bool = False,
        skip_if_exists: bool = True
    ) -> Dict[str, Any]:
        """
        1. File Create - ส่งไฟล์เข้าวิเคราะห์

        Args:
            file_path: path ของไฟล์ที่จะส่ง
            machine: VM ที่จะใช้วิเคราะห์ (optional)
            is_pcap: True ถ้าไฟล์เป็น PCAP
            skip_if_exists: ถ้า True จะเช็คก่อนว่ามี task เดิมอยู่ไหม

        Returns:
            ผลการสร้าง task
        """
        # เช็คว่ามี task เดิมอยู่ไหม
        if skip_if_exists:
            existing_task_id = self.check_file_exists(file_path)
            if existing_task_id:
                return {
                    "status": "exists",
                    "task_id": existing_task_id,
                    "message": f"File already analyzed. Task ID: {existing_task_id}"
                }

        url = f"{self.base_url}/apiv2/tasks/create/file/"

        # Prepare files and data
        files = {'file': open(file_path, 'rb')}
        data = {}

        if machine:
            data['machine'] = machine

        if is_pcap:
            data['pcap'] = '1'

        try:
            response = requests.post(url, files=files, data=data, headers=self.headers)
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
        """
        3. Task Status - ตรวจสอบสถานะการวิเคราะห์

        Args:
            task_id: ID ของ task

        Returns:
            สถานะของ task
        """
        url = f"{self.base_url}/apiv2/tasks/status/{task_id}/"

        try:
            response = requests.get(url, headers=self.headers)
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
        """
        รอให้ task วิเคราะห์เสร็จ

        Args:
            task_id: ID ของ task
            timeout: timeout ในหน่วยวินาที (default: 600 = 10 นาที)
            poll_interval: ระยะเวลาระหว่างการเช็คสถานะ (วินาที)
            verbose: แสดงสถานะระหว่างรอ

        Returns:
            True ถ้าเสร็จ, False ถ้า timeout
        """
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
    ) -> Dict[str, Any]:
        """
        4. Task Report - ดึงรายงานผลการวิเคราะห์

        Args:
            task_id: ID ของ task
            report_format: รูปแบบรายงาน (json/maec/maec5/metadata/lite/all)
            download_zip: ดาวน์โหลดเป็น zip หรือไม่

        Returns:
            รายงานผลการวิเคราะห์
        """
        url = f"{self.base_url}/apiv2/tasks/get/report/{task_id}/{report_format}/"

        if download_zip:
            url += "zip/"

        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()

            if download_zip:
                return {"status": "success", "content": response.content, "type": "zip"}
            else:
                return {"status": "success", "data": response.json()}
        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e)}

    def filter_report_for_llm(self, task_id: int) -> Dict[str, Any]:
        """
        ดึงรายงานและ Filter เฉพาะส่วนที่สำคัญสำหรับ LLM
        (Signatures, Network, Static)

        Args:
            task_id: ID ของ task

        Returns:
            รายงานที่ถูก filter แล้ว
        """
        report = self.get_task_report(task_id)

        if report.get("status") != "success":
            return report

        data = report.get("data", {})

        # Filter เฉพาะส่วนที่ต้องการ
        filtered_data = {
            "task_id": task_id,
            "target": data.get("target", {}),
            "signatures": data.get("signatures", []),
            "network": data.get("network", {}),
            "static": data.get("static", {}),
            "info": data.get("info", {}),
            "behavior": {
                "summary": data.get("behavior", {}).get("summary", {}),
            }
        }

        return {
            "status": "success",
            "data": filtered_data
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
        """
        วิเคราะห์ไฟล์แบบครบวงจร (สร้าง task -> รอเสร็จ -> ดึงรายงาน)

        Args:
            file_path: path ของไฟล์
            machine: VM ที่จะใช้
            is_pcap: ไฟล์เป็น PCAP หรือไม่
            wait: รอให้วิเคราะห์เสร็จหรือไม่
            timeout: timeout สำหรับการรอ
            get_filtered_report: ดึงรายงานที่ filter แล้วหรือไม่

        Returns:
            ผลการวิเคราะห์ครบวงจร
        """
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
if __name__ == "__main__":
    # สร้าง instance
    cape = CAPEAnalyzer()
    # หรือถ้ามี API Token
    # cape = CAPEAnalyzer(api_token="YOUR_TOKEN_HERE")

    # ตัวอย่างที่ 1: เช็คว่าไฟล์เคยถูกวิเคราะห์แล้วหรือไม่
    print("=== Example 1: Check if file exists ===")
    task_id = cape.check_file_exists("malware_sample.exe")
    if task_id:
        print(f"File already analyzed! Task ID: {task_id}")
    else:
        print("File not found in database")

    # ตัวอย่างที่ 2: ส่งไฟล์เข้าวิเคราะห์
    print("\n=== Example 2: Submit file for analysis ===")
    result = cape.create_file_task("malware_sample.exe", skip_if_exists=True)
    print(f"Result: {result}")

    # ตัวอย่างที่ 3: เช็คสถานะของ task
    print("\n=== Example 3: Check task status ===")
    if result.get("task_id"):
        status = cape.get_task_status(result["task_id"])
        print(f"Status: {status}")

    # ตัวอย่างที่ 4: ดึงรายงานแบบ filtered สำหรับ LLM
    print("\n=== Example 4: Get filtered report ===")
    if result.get("task_id"):
        # รอให้วิเคราะห์เสร็จก่อน
        if cape.wait_for_task(result["task_id"], timeout=300):
            report = cape.filter_report_for_llm(result["task_id"])
            print(f"Report: {report}")

    # ตัวอย่างที่ 5: วิเคราะห์ไฟล์แบบครบวงจร (แนะนำ!)
    print("\n=== Example 5: Complete analysis ===")
    full_result = cape.analyze_file_complete(
        file_path="malware_sample.exe",
        wait=True,
        timeout=600,
        get_filtered_report=True
    )
    print(f"Complete result: {full_result}")

    # ตัวอย่างที่ 6: วิเคราะห์ PCAP file
    print("\n=== Example 6: Analyze PCAP file ===")
    pcap_result = cape.analyze_file_complete(
        file_path="network_traffic.pcap",
        is_pcap=True,
        wait=True
    )
    print(f"PCAP result: {pcap_result}")
