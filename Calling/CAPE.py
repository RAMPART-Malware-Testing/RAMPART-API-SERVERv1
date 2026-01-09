import os
import requests
import hashlib
import time
from typing import Optional, Dict, Any
from dotenv import load_dotenv
import json

load_dotenv()    

from typing import Dict, Any, List, Optional
import json

class CleanCapeReport:
    def __init__(self, json_data):
        if json_data is None:return None
        # รับ JSON Data (ที่เป็น Dict อยู่แล้ว) เข้ามา
        self.data = json_data.get("data")

    def get_cape_score(self):
        if not self.data:
            return 0
        return self.data.get("malscore", 0)

    def get_malware_family(self):
        detections = self.data.get("detections", [])
        if detections and isinstance(detections, list):
            families = set()
            for item in detections:
                family_name = item.get("family")
                if family_name:
                    families.add(family_name)
            
            # ถ้าเจอ ให้รวมชื่อแล้วส่งกลับ (เช่น "QuasarStealer, QuasarRAT")
            if families:
                return ", ".join(list(families))
        return None

    def get_mitre_ttps(self):
        """
        ดึงข้อมูล MITRE ATT&CK TTPs
        สิ่งนี้สำคัญมากสำหรับ AI เพราะมันบอก 'เจตนา' ของไฟล์ (เช่น ขโมยข้อมูล, ซ่อนตัว)
        """
        if not self.data:
            return []

        ttps_set = set() # ใช้ Set เพื่อตัดตัวซ้ำ
        
        # CAPE มักเก็บ TTPs ไว้ใน top-level key 'ttps'
        raw_ttps = self.data.get("ttps", [])
        
        if isinstance(raw_ttps, list):
            for ttp_group in raw_ttps:
                # บางเวอร์ชันเป็น list of strings เลย, บางเวอร์ชันเป็น dict
                if isinstance(ttp_group, str):
                     ttps_set.add(ttp_group)
                elif isinstance(ttp_group, dict):
                    # ดึงจาก list ข้างในอีกที
                    sub_ttps = ttp_group.get("ttps", [])
                    for t_id in sub_ttps:
                        ttps_set.add(t_id)

        # แปลงกลับเป็น list เพื่อให้ serializable เป็น JSON
        return list(ttps_set)

    def get_signatures(self):
        """
        ดึงพฤติกรรมที่น่าสงสัย (Signatures)
        คัดเฉพาะที่มี Severity สูงๆ เพื่อไม่ให้รก
        """
        if not self.data:
            return []

        signatures = []
        raw_sigs = self.data.get("signatures", [])
        
        for sig in raw_sigs:
            # ดึงเฉพาะข้อมูลที่จำเป็น
            signatures.append({
                "name": sig.get("name"),
                "description": sig.get("description"),
                "severity": sig.get("severity", 1)
            })
            
        # เรียงลำดับจากความรุนแรงมาก -> น้อย
        signatures.sort(key=lambda x: x['severity'], reverse=True)
        
        # ส่งคืนแค่ Top 10 เพื่อประหยัด Token แต่ได้เนื้อหาเน้นๆ
        return signatures[:10]

    def get_network_activity(self):
        """
        ดึงข้อมูล Network ฉบับปรับปรุง (รองรับ Raw IP/TCP)
        """
        if not self.data:
            return {}
            
        network = self.data.get("network", {})
        
        # 1. HTTP Requests (High Level) - ดูว่าเปิดเว็บอะไร
        http_reqs = []
        for req in network.get("http", [])[:5]:
            http_reqs.append({
                "url": req.get("uri"),
                "host": req.get("host"),
                "method": req.get("method")
            })

        # 2. DNS Queries (High Level) - ดูว่าถามหาโดเมนอะไร
        dns_reqs = []
        for dns in network.get("dns", [])[:5]:
            dns_reqs.append({
                "request": dns.get("request"),
                "answer": dns.get("answers", [])
            })

        # 3. Raw IP Connections (Low Level) - *** เพิ่มส่วนนี้ครับ ***
        # กรณีที่ไม่มี HTTP/DNS เราต้องดูว่ามันยิง IP ไปไหนบ้าง
        # เราจะรวมข้อมูลจาก 'hosts' และ 'tcp' เข้าด้วยกัน
        
        connected_ips = {} # ใช้ Dict เพื่อตัด IP ซ้ำ
        
        # 3.1 ดึงจาก hosts (สรุปปลายทาง)
        for host in network.get("hosts", []):
            ip = host.get("ip")
            # กรอง Local IP ของ Sandbox ทิ้ง (มักจะเป็น Gateway/Broadcast)
            if ip in ["192.168.122.1", "192.168.122.255", "127.0.0.1", "0.0.0.0"]:
                continue
                
            connected_ips[ip] = {
                "dst_ip": ip,
                "country": host.get("country_name", "unknown"),
                "ports": host.get("ports", [])
            }

        # 3.2 ดึงจาก tcp (Traffic จริง) - เผื่อมี IP ที่ไม่อยู่ใน hosts
        for tcp in network.get("tcp", []):
            dst = tcp.get("dst")
            dport = tcp.get("dport")
            
            # กรอง Local IP
            if dst.startswith("192.168.") or dst == "127.0.0.1":
                continue
            
            # ถ้า IP นี้มีอยู่แล้ว ให้เพิ่ม Port เข้าไป
            if dst in connected_ips:
                if dport not in connected_ips[dst]["ports"]:
                    connected_ips[dst]["ports"].append(dport)
            else:
                # ถ้าเป็น IP ใหม่
                connected_ips[dst] = {
                    "dst_ip": dst,
                    "country": "unknown", # ใน TCP ไม่มีบอกประเทศ
                    "ports": [dport]
                }

        # แปลงกลับเป็น List และเอาแค่ 10 ไอพีแรก
        raw_connections = list(connected_ips.values())[:10]

        return {
            "http_traffic": http_reqs,
            "dns_queries": dns_reqs,
            "ip_connections": raw_connections # ส่งอันนี้ให้ AI ดูเพิ่ม
        }

    def get_behavior_summary(self):
        """สรุปการกระทำกับไฟล์และระบบ"""
        if not self.data:
            return {}
            
        summary = self.data.get("behavior", {}).get("summary", {})
        
        def limit_list(key):
            return summary.get(key, [])[:5] # ตัดเหลือ 5 บรรทัด

        return {
            "files_written": limit_list("files"),
            "registry_keys_modified": limit_list("keys"),
            "commands_executed": limit_list("command_line") # สำคัญ: ดูว่าสั่ง CMD อะไรบ้าง
        }

    def clean_data(self):
        """รวมข้อมูลทั้งหมดเป็น JSON ก้อนเล็ก"""
        if not self.data:
            return None

        return {
            "source": "CAPE Sandbox",
            "score": self.get_cape_score(),
            "malware_family": self.get_malware_family(),
            "mitre_attack_techniques": self.get_mitre_ttps(),
            "critical_signatures": self.get_signatures(),
            "network_behavior": self.get_network_activity(),
            "system_behavior": self.get_behavior_summary()
        }

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
        clean_data = CleanCapeReport(report)
        return {"status": "success", "data": clean_data.clean_data()}

# (ลบ Method MobSF ที่หลุดเข้ามา: scan_file, get_report_json)
# (ลบ Test Code ท้ายไฟล์)