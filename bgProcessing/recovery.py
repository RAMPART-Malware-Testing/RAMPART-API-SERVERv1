import json
import threading
import time
from pathlib import Path

from celery.result import AsyncResult
from celery.signals import worker_ready
from sqlalchemy import select

from bgProcessing.celery_app import celery_app
from bgProcessing.tasks import (
    Analysis,
    SyncSessionLocal,
    analyze_malware_task,
    publish_progress,
    update_task_rows,
)
from cores.redis import redis_client

STALE_STATUSES = ("processing", "analyzing")
SETTLE_SECONDS = 10
SWEEP_INTERVAL_SECONDS = 300
MAX_RECOVERY_ATTEMPTS = 2
RECOVERY_COUNTER_TTL_SECONDS = 6 * 60 * 60
MASTER_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "master_config.json"


def vt_hash_check_enabled_from_config() -> bool:
    try:
        config = json.loads(MASTER_CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return True
    if not isinstance(config, dict):
        return True
    return config.get("VIRUSTOTAL_HASH_CHECK_ENABLED", True)


def _task_owner_alive(task_id: str) -> bool:
    result = AsyncResult(id=task_id, app=celery_app)
    state = result.state
    if state == "RETRY":
        # Waiting on a countdown retry: the message is parked in the broker, not orphaned.
        return True
    if state != "STARTED":
        return False
    info = result.info
    if not isinstance(info, dict):
        return True
    pid = info.get("pid")
    return not isinstance(pid, int) or Path(f"/proc/{pid}").exists()


def _recovery_attempts(task_id: str) -> int:
    key = f"analysis_recovery:{task_id}"
    attempts = int(redis_client.incr(key))
    redis_client.expire(key, RECOVERY_COUNTER_TTL_SECONDS)
    return attempts


def sweep_orphaned_tasks() -> dict:
    counts = {"requeued": 0, "active": 0, "dropped": 0, "failed": 0}
    db = SyncSessionLocal()
    try:
        rows = db.execute(
            select(Analysis).where(Analysis.status.in_(STALE_STATUSES))
        ).scalars().all()

        for row in rows:
            task_id = str(row.task_id)
            if _task_owner_alive(task_id):
                counts["active"] += 1
                continue

            if not row.file_path or not Path(row.file_path).is_file():
                update_task_rows(db, task_id, "failed", STALE_STATUSES)
                db.commit()
                publish_progress(
                    task_id,
                    "failed",
                    "ไม่สามารถกู้คืนการวิเคราะห์ได้เนื่องจากไม่พบไฟล์ต้นฉบับในระบบ",
                    error="source file missing after worker restart",
                )
                counts["dropped"] += 1
                continue

            if _recovery_attempts(task_id) > MAX_RECOVERY_ATTEMPTS:
                update_task_rows(db, task_id, "failed", STALE_STATUSES)
                db.commit()
                publish_progress(
                    task_id,
                    "failed",
                    "การวิเคราะห์ถูกขัดจังหวะหลายครั้ง กรุณาเริ่มวิเคราะห์ไฟล์นี้อีกครั้ง",
                    error="analysis interrupted repeatedly by worker restarts",
                )
                counts["failed"] += 1
                continue

            update_task_rows(db, task_id, "queued", STALE_STATUSES)
            db.commit()
            analyze_malware_task.apply_async(
                args=(row.file_path, row.md5, row.file_hash, row.file_size or 0),
                kwargs={"enable_vt_hash_check": vt_hash_check_enabled_from_config()},
                task_id=task_id,
            )
            publish_progress(
                task_id,
                "queued",
                "ระบบกู้คืนงานวิเคราะห์ที่ค้างจากการรีสตาร์ท worker แล้ว",
            )
            counts["requeued"] += 1
    finally:
        db.close()
    return counts


def _run_sweep(label: str) -> None:
    try:
        counts = sweep_orphaned_tasks()
    except Exception as exc:
        print(f"[recovery] {label} failed: {exc!r}")
        return
    if any(counts.values()):
        print(f"[recovery] {label}: {counts}")


def _start_periodic_sweep() -> None:
    if getattr(_start_periodic_sweep, "started", False):
        return
    _start_periodic_sweep.started = True

    def loop() -> None:
        while True:
            time.sleep(SWEEP_INTERVAL_SECONDS)
            _run_sweep("periodic sweep")

    threading.Thread(target=loop, name="orphan-sweep", daemon=True).start()


@worker_ready.connect
def recover_orphaned_tasks(sender=None, **_):
    time.sleep(SETTLE_SECONDS)
    _run_sweep("orphaned tasks after worker start")
    _start_periodic_sweep()
