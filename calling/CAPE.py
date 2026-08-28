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

        ttps_set = set()
        
        raw_ttps = self.data.get("ttps", [])
        
        if isinstance(raw_ttps, list):
            for ttp_group in raw_ttps:
                if isinstance(ttp_group, str):
                     ttps_set.add(ttp_group)
                elif isinstance(ttp_group, dict):
                    sub_ttps = ttp_group.get("ttps", [])
                    for t_id in sub_ttps:
                        ttps_set.add(t_id)

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
            signatures.append({
                "name": sig.get("name"),
                "description": sig.get("description"),
                "severity": sig.get("severity", 1)
            })
            
        signatures.sort(key=lambda x: x['severity'], reverse=True)
        
        return signatures[:10]

    def get_network_activity(self):
        """
        ดึงข้อมูล Network ฉบับปรับปรุง (รองรับ Raw IP/TCP)
        """
        if not self.data:
            return {}
            
        network = self.data.get("network", {})
        
        http_reqs = []
        for req in network.get("http", [])[:5]:
            http_reqs.append({
                "url": req.get("uri"),
                "host": req.get("host"),
                "method": req.get("method")
            })

        dns_reqs = []
        for dns in network.get("dns", [])[:5]:
            dns_reqs.append({
                "request": dns.get("request"),
                "answer": dns.get("answers", [])
            })

        
        connected_ips = {}
        
        for host in network.get("hosts", []):
            ip = host.get("ip")
            if ip in ["192.168.122.1", "192.168.122.255", "127.0.0.1", "0.0.0.0"]:
                continue
                
            connected_ips[ip] = {
                "dst_ip": ip,
                "country": host.get("country_name", "unknown"),
                "ports": host.get("ports", [])
            }

        for tcp in network.get("tcp", []):
            dst = tcp.get("dst")
            dport = tcp.get("dport")
            
            if dst.startswith("192.168.") or dst == "127.0.0.1":
                continue
            
            if dst in connected_ips:
                if dport not in connected_ips[dst]["ports"]:
                    connected_ips[dst]["ports"].append(dport)
            else:
                connected_ips[dst] = {
                    "dst_ip": dst,
                    "country": "unknown",
                    "ports": [dport]
                }

        raw_connections = list(connected_ips.values())[:10]

        return {
            "http_traffic": http_reqs,
            "dns_queries": dns_reqs,
            "ip_connections": raw_connections
        }

    def get_behavior_summary(self):
        """สรุปการกระทำกับไฟล์และระบบ"""
        if not self.data:
            return {}
            
        summary = self.data.get("behavior", {}).get("summary", {})
        
        def limit_list(key):
            return summary.get(key, [])[:5]

        return {
            "files_written": limit_list("files"),
            "registry_keys_modified": limit_list("keys"),
            "commands_executed": limit_list("command_line")
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
        try:
            file_hash = self.calculate_hash(file_path, hash_type)
        except OSError as e:
            return {"error": str(e), "data": None}
        url = f"{self.base_url}/apiv2/tasks/search/{hash_type}/{file_hash}/"
        try:
            response = requests.get(url, timeout=30)
            js = response.json()
            return js.get("data")
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}

    def delete_taskID(self, task_id):
        try:
            requests.get(f"{self.base_url}/apiv2/tasks/delete/{task_id}", timeout=30)
        except: pass

    def create_file_task(self, file_path: str, machine: Optional[str] = None, package: Optional[str] = None, is_pcap: bool = False) -> Dict[str, Any]:
        url = f"{self.base_url}/apiv2/tasks/create/file/"
        try:
            files = {'file': open(file_path, 'rb')}
        except OSError as e:
            return {"status": "error", "error": str(e)}
        data = {}
        if machine: data['machine'] = machine
        if package: data['package'] = package
        if is_pcap: data['pcap'] = '1'

        try:
            response = requests.post(url, files=files, data=data, timeout=30)
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
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e), "data": None}

    def get_task_report(self, task_id: int, report_format: str = "json"):
        url = f"{self.base_url}/apiv2/tasks/get/report/{task_id}/{report_format}/"
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            return {"status": "success", "data": response.json()}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def get_report(self, task_id: int, md5 :str ):
        return self.get_task_report(task_id)

