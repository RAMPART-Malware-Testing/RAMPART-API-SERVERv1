import json

class CleanCapeReport:
    def __init__(self, json_data):
        self.data = json_data

    def get_behavior_summary(self):
        """ดึงพฤติกรรมไฟล์ (จำกัดจำนวนเพื่อประหยัด Token)"""
        if not self.data:
            return {}
        
        summary = self.data.get("behavior", {}).get("summary", {})
        
        # Helper function to limit list items
        def get_top_items(key, limit=5):
            items = summary.get(key, [])
            return items[:limit] # เอาแค่ 5 อันแรกพอ AI เข้าใจ pattern

        return {
            "files_touched": get_top_items("files"),
            "registry_keys_modified": get_top_items("keys"),
            "mutexes_created": get_top_items("mutexes"),
            "processes_created": get_top_items("processes") # สำคัญ: ดูว่ามีการแตก Process ลูกไหม
        }

    def get_network_activity(self):
        """ดึงข้อมูล Network ที่ละเอียดขึ้น (DNS + HTTP)"""
        if not self.data:
            return {}
            
        network = self.data.get("network", {})
        
        # ดึง HTTP requests (สำคัญมาก ใช้ดู C2 Communication)
        http_requests = []
        for req in network.get("http", [])[:5]: # เอาแค่ 5 request แรก
            http_requests.append({
                "url": req.get("uri"),
                "method": req.get("method"),
                "host": req.get("host")
            })

        # ดึง DNS queries
        dns_queries = []
        for dns in network.get("dns", [])[:5]:
            dns_queries.append({
                "request": dns.get("request"),
                "answer": dns.get("answers", [])
            })

        return {
            "http_traffic": http_requests,
            "dns_queries": dns_queries,
            "hosts_connected": network.get("hosts", [])[:5]
        }

    def get_signatures_and_malware(self):
        """ดึง Signature และชื่อมัลแวร์ (ถ้ามี)"""
        if not self.data:
            return {"signatures": [], "malware_family": None}

        # 1. Malware Family (ถ้า CAPE ฟันธงได้)
        malware_family = self.data.get("malware_family")
        
        # 2. Signatures (เอาเฉพาะที่มี score สูงๆ หรือเป็นภัยคุกคาม)
        signatures = []
        for sig in self.data.get("signatures", []):
            # กรองเอาเฉพาะ Signature ที่ดูมีน้ำหนัก (severity > 1 หรือมี weight)
            # แต่เพื่อความง่าย ดึงชื่อกับคำอธิบายมาเลย
            signatures.append({
                "name": sig.get("name"),
                "description": sig.get("description"),
                "severity": sig.get("severity", 1) # ระดับความรุนแรง
            })
            
        # 3. MITRE ATT&CK (ถ้ามีใน report อาจจะอยู่ใน signatures หรือ ttps)
        # ส่วนใหญ่ CAPE จะ map signature เข้ากับ mitre อยู่แล้วใน description

        return {
            "malware_family": malware_family,
            "signatures": signatures[:10] # เอาแค่ Top 10 ที่รุนแรงที่สุด
        }

    def clean_data(self):
        """ฟังก์ชันหลักสำหรับเรียกใช้งาน"""
        if not self.data:
            return None

        behavior = self.get_behavior_summary()
        network = self.get_network_activity()
        sigs = self.get_signatures_and_malware()

        cleaned_report = {
            "malware_identification": sigs["malware_family"], # เช่น "Emotet", "WannaCry"
            "critical_signatures": sigs["signatures"],        # พฤติกรรมที่น่าสงสัย
            "network_behavior": network,                      # การเชื่อมต่อเน็ต
            "system_behavior": behavior,                      # การแก้ไขไฟล์/Registry
            "cape_score": self.data.get("malscore", 0)        # คะแนนความเสี่ยงจาก CAPE (ถ้ามี)
        }
        
        return cleaned_report