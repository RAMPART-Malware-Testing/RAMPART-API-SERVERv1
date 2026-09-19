import os
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

STALE_STATUSES = ("processing", "analyzing")
SETTLE_SECONDS = 10


def _task_owner_alive(task_id: str) -> bool:
    result = AsyncResult(id=task_id, app=celery_app)
    if result.state != "STARTED":
        return False
    info = result.info
    if not isinstance(info, dict):
        return False
    pid = info.get("pid")
    return isinstance(pid, int) and Path(f"/proc/{pid}").exists()


@worker_ready.connect
def recover_orphaned_tasks(sender=None, **_):
    time.sleep(SETTLE_SECONDS)
    db = SyncSessionLocal()
    try:
        rows = db.execute(
            select(Analysis).where(Analysis.status.in_(STALE_STATUSES))
        ).scalars().all()
        if not rows:
            return

        recovered = 0
        active = 0
        dropped = 0
        for row in rows:
            task_id = str(row.task_id)
            if _task_owner_alive(task_id):
                active += 1
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
                dropped += 1
                continue

            update_task_rows(db, task_id, "queued", STALE_STATUSES)
            db.commit()
            analyze_malware_task.apply_async(
                args=(row.file_path, row.md5, row.file_hash, row.file_size or 0),
                task_id=task_id,
            )
            publish_progress(
                task_id,
                "queued",
                "ระบบกู้คืนงานวิเคราะห์ที่ค้างจากการรีสตาร์ท worker แล้ว",
            )
            recovered += 1

        if recovered or active or dropped:
            print(
                f"[recovery] orphaned tasks after worker start: "
                f"requeued={recovered} still_active={active} dropped={dropped}"
            )
    except Exception as exc:
        print(f"[recovery] failed to recover orphaned tasks: {exc!r}")
    finally:
        db.close()
