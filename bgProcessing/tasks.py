import os
import redis
from dotenv import load_dotenv
from sqlalchemy import select
from celery.exceptions import Retry

from bgProcessing.celery_app import celery_app
from cores.sync_pg_db import SyncSessionLocal
from cores.models_class import Analysis, Reports

# นำเข้าฟังก์ชันจากไฟล์ย่อยที่เราแยกไว้
from bgProcessing.task_utils import map_final_data_to_report, predict_rampart_ai
from bgProcessing.task_handlers import handle_virustotal

load_dotenv()

# ตั้งค่า Redis
REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = os.environ.get("REDIS_PORT", "6379")
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", "")
REDIS_URL = f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/0" if REDIS_PASSWORD else f"redis://{REDIS_HOST}:{REDIS_PORT}/0"
redis_client = redis.StrictRedis.from_url(REDIS_URL)

@celery_app.task(bind=True, max_retries=100)
def analyze_malware_task(
    self,
    file_path: str,
    md5: str,           # <--- อัปเดตพารามิเตอร์ให้ตรงกับที่ Controller ส่งมา
    sha256: str,        # <--- อัปเดตพารามิเตอร์ให้ตรงกับที่ Controller ส่งมา
    total_size: int,    # <--- อัปเดตพารามิเตอร์ให้ตรงกับที่ Controller ส่งมา
    analysis_tool: str = '',
    virustotal=None,
    cape=None,
    mobsf=None,
    predict_retried: int = 0,
):
    db = SyncSessionLocal()
    analy = None
    
    try:
        # 1. เช็ค Database
        stmt = select(Analysis).where(Analysis.file_hash == sha256).limit(1)
        analy = db.execute(stmt).scalar_one_or_none()

        if not analy:
            return {"success": False, "message": f"Analysis not found for hash={sha256}"}

        print(f"#######################[ Celery Task ID: {self.request.id} ]#######################")
        
        # ==========================================================================
        # พื้นที่สำหรับทดสอบ (คอมเมนต์ไว้เพื่อไม่ให้ทำงานจริง ทดสอบเปิดทีละส่วนได้เลยครับ)
        # ==========================================================================
        
        # --- 1. ทดสอบ VirusTotal ---
        # if cape_task_id is None and "virustotal" not in results and "vt_skipped" not in results:
        #     results = handle_virustotal(file_path, md5, total_size, results)

        # --- 2. ทดสอบ MobSF ---
        # (รอใส่เงื่อนไขเรียกใช้ handle_mobsf)

        # --- 3. ทดสอบ CAPE ---
        # (รอใส่เงื่อนไขเรียกใช้ handle_cape)

        # --- 4. ทดสอบ Gemini AI ---
        # (รอใส่เงื่อนไขเรียกใช้ API)

        # --- 5. บันทึกผลลัพธ์ลง DB ---
        # (รอใส่เงื่อนไขบันทึกลงตาราง Reports และ Analysis)
        
        # ==========================================================================

        # ปล่อยให้ Task จบการทำงานไปก่อนระหว่างการทดสอบ
        db.commit()
        print(f"[DONE] Task reached the end (Test Mode): {self.request.id}")
        return {"success": True, "task_id": self.request.id}

    except Retry:
        raise
    except Exception as e:
        print(f"[ERROR] Task failed: {e}")
        try:
            db.rollback()
            if analy:
                analy.status = "failed"
                db.commit()
        except:
            pass
        raise
    finally:
        db.close()