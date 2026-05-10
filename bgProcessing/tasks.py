# tasks.py
import os
import json
import redis
from dotenv import load_dotenv
from sqlalchemy import select
from celery.exceptions import Retry

from bgProcessing.celery_app import celery_app
from cores.sync_pg_db import SyncSessionLocal
from cores.Schema.schema_class import Analysis, Reports

from bgProcessing.task_utils import map_final_data_to_report, predict_rampart_ai
from bgProcessing.task_handlers import handle_virustotal

load_dotenv()

REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = os.environ.get("REDIS_PORT", "6379")
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", "")
REDIS_URL = f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/0" if REDIS_PASSWORD else f"redis://{REDIS_HOST}:{REDIS_PORT}/0"
redis_client = redis.StrictRedis.from_url(REDIS_URL)

@celery_app.task(bind=True, max_retries=10)
def analyze_malware_task(
    self,
    file_path: str,
    md5: str,
    sha256: str,
    total_size: int,
    analysis_tool: str = '',
    virustotal: str = None,
    cape: str = None,
    mobsf: str = None,
    predict_retried: int = 0,
    vt_retry_count: int = 0
):
    db = SyncSessionLocal()
    analy = None
    
    try:
        stmt = select(Analysis).where(Analysis.file_hash == sha256).limit(1)
        analy = db.execute(stmt).scalar_one_or_none()

        if not analy:
            return {"success": False, "message": f"Analysis not found for hash={sha256}"}

        # VirusTotal Phase
        if not virustotal:
            is_vt_retry = vt_retry_count > 0
            results = handle_virustotal(file_path, md5, total_size, is_retry=is_vt_retry)
            
            if results.get("success"):
                vt_data = results.get("data")
                malicious_count = vt_data.get('virustotal', {}).get('scan_summary', {}).get('malicious_count', 0)
                
                # Halt pipeline if VT detects severe threat
                if malicious_count >= 3:
                    analy.is_malicious = True
                    analy.blocked_by = 'virustotal'
                    analy.status = 'success'
                    db.commit()
                    return {"success": True, "message": "Malware detected at VT phase. Pipeline stopped."}

                os.makedirs("reports", exist_ok=True)
                report_path = os.path.join("reports", f"vt-{md5}.json")
                with open(report_path, 'w', encoding='utf-8') as f:
                    json.dump(vt_data, f, indent=4)
                    
                virustotal = report_path
                
            elif results.get("skip"):
                virustotal = "skipped"
            else:
                retry_delay = results.get('retry', 60)
                raise self.retry(countdown=retry_delay, kwargs={
                    'file_path': file_path,
                    'md5': md5,
                    'sha256': sha256,
                    'total_size': total_size,
                    'analysis_tool': analysis_tool,
                    'virustotal': virustotal,
                    'cape': cape,
                    'mobsf': mobsf,
                    'predict_retried': predict_retried,
                    'vt_retry_count': vt_retry_count + 1
                })

        # MobSF Phase
        # TODO: Implement MobSF handler

        # CAPE Phase
        # TODO: Implement CAPE handler

        # Gemini AI Phase
        # TODO: Implement AI aggregation and DB reporting updates

        return {"success": True, "task_id": self.request.id}

    except Retry:
        raise
    except Exception as e:
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