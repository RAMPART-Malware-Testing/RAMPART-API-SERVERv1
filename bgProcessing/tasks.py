import json
from pathlib import Path

from celery.exceptions import MaxRetriesExceededError, Retry
from sqlalchemy import select, text, update

from bgProcessing.celery_app import celery_app
from bgProcessing.task_handlers import (
    calculate_cape_danger_score,
    calculate_mobsf_danger_score,
    calculate_threat_scoreVT,
    get_malicious_virustotal_results,
    handle_cape,
    handle_mobsf,
    handle_virustotal,
    write_raw_virustotal_report,
)
from cores.Schema.schema_class import Analysis, Reports
from cores.sync_pg_db import SyncSessionLocal


REPORTS_DIR = Path("reports")
ACTIVE_STATUSES = ("dispatching", "queued", "processing")
FINALIZABLE_STATUSES = ("processing", "success")
MAX_SANDBOX_POLLS = 10


class TaskFinalizationError(RuntimeError):
    pass


def update_task_rows(db, task_id: str, status: str, from_statuses: tuple[str, ...], **values) -> int:
    statement = update(Analysis).where(
        Analysis.task_id == task_id,
        Analysis.status.in_(from_statuses),
    )
    result = db.execute(statement.values(status=status, **values))
    return result.rowcount


def fail_task(db, task_id: str, error) -> dict:
    message = str(error)
    db.rollback()
    update_task_rows(db, task_id, "failed", ACTIVE_STATUSES)
    db.commit()
    return {"success": False, "task_id": task_id, "error": message}


def read_report(path: str | Path) -> dict:
    with Path(path).open("r", encoding="utf-8") as file:
        return json.load(file)


def virustotal_report_values(report: dict) -> tuple[list[str], bool]:
    attributes = report.get("data", {}).get("attributes", {})
    if not attributes:
        signatures = report.get("threats_found", {}).get("malicious", [])
        return signatures, bool(signatures)

    malicious_results = get_malicious_virustotal_results(report)
    signatures = [
        f"{engine}: {result.get('result')}"
        for engine, result in malicious_results.items()
    ]
    return signatures, bool(malicious_results)


def read_sandbox_score(path: str | None, calculator):
    if not path:
        return None
    try:
        return calculator(read_report(path))
    except (OSError, json.JSONDecodeError, AttributeError, TypeError, ValueError):
        return None


def task_is_complete(db, task_id: str) -> bool:
    statuses = db.execute(
        select(Analysis.status).where(Analysis.task_id == task_id)
    ).scalars().all()
    return bool(statuses) and all(status == "success" for status in statuses)


def finalize_analysis_report(
    db,
    task_id: str,
    file_path: str,
    vt_report_path: str,
    *,
    mobsf_report_path: str | None = None,
    cape_report_path: str | None = None,
    tools: str = "virustotal",
):
    try:
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:task_id, 0))"),
            {"task_id": task_id},
        )
        rows = db.execute(
            select(Analysis).where(Analysis.task_id == task_id)
        ).scalars().all()
        if not rows:
            raise TaskFinalizationError("Task rows not found")
        if any(row.status not in FINALIZABLE_STATUSES for row in rows):
            raise TaskFinalizationError("Task rows are not in a finalizable state")

        report_ids = {row.rid for row in rows if row.rid is not None}
        if len(report_ids) > 1 or (report_ids and any(row.rid is None for row in rows)):
            raise TaskFinalizationError("Inconsistent report association")

        vt_report = read_report(vt_report_path)
        scores = {
            "virustotal_score": calculate_threat_scoreVT(vt_report),
            "mobsf_score": read_sandbox_score(mobsf_report_path, calculate_mobsf_danger_score),
            "cape_score": read_sandbox_score(cape_report_path, calculate_cape_danger_score),
        }
        signatures, malicious = virustotal_report_values(vt_report)
        if report_ids:
            report = db.get(Reports, next(iter(report_ids)))
            if report is None:
                raise TaskFinalizationError("Associated report not found")
            report.virustotal_score = scores["virustotal_score"]
            report.mobsf_score = scores["mobsf_score"]
            report.cape_score = scores["cape_score"]
            report.malware_signatures = signatures
        else:
            report = Reports(
                file_type=Path(file_path).suffix.lstrip(".") or None,
                **scores,
                malware_signatures=signatures,
            )
            db.add(report)
            db.flush()

        values = {"status": "success", "rid": report.rid, "tools": tools}
        if malicious:
            values.update(is_malicious=True, blocked_by="virustotal")
        result = db.execute(
            update(Analysis)
            .where(
                Analysis.task_id == task_id,
                Analysis.status.in_(FINALIZABLE_STATUSES),
            )
            .values(**values)
        )
        if result.rowcount <= 0:
            raise TaskFinalizationError("Terminal update did not associate task rows")
        if result.rowcount != len(rows):
            raise TaskFinalizationError("Task rows were not fully associated")

        verified = db.execute(
            select(Analysis).where(Analysis.task_id == task_id)
        ).scalars().all()
        if len(verified) != len(rows) or any(
            row.status != "success" or row.rid != report.rid for row in verified
        ):
            raise TaskFinalizationError("Task rows were not fully associated")
        return report, scores
    except Exception:
        db.rollback()
        raise


def finalize_virustotal_report(db, task_id: str, file_path: str, report_data: dict):
    report_path = REPORTS_DIR / f"virustotal-{task_id}.json"
    write_raw_virustotal_report(report_data, report_path)
    report, scores = finalize_analysis_report(
        db, task_id, file_path, str(report_path), tools="virustotal"
    )
    return report, scores["virustotal_score"]


@celery_app.task(bind=True, max_retries=30)
def analyze_malware_task(
    self,
    file_path: str,
    md5: str,
    sha256: str,
    total_size: int,
    vt_status=None,
    vt_report_path: str | None = None,
    mobsf_report_path: str | None = None,
    mobsf_submitted: bool = False,
    mobsf_poll_count: int = 0,
    cape_report_path: str | None = None,
    cape_task_id=None,
    cape_poll_count: int = 0,
):
    db = SyncSessionLocal()
    task_id = self.request.id

    try:
        started = update_task_rows(db, task_id, "processing", ("dispatching", "queued"))
        db.commit()
        if not started and (
            task_is_complete(db, task_id)
            or self.request.retries == 0 and not any((vt_report_path, mobsf_report_path, cape_report_path, mobsf_submitted, cape_task_id))
        ):
            return {"success": True, "task_id": task_id, "state": "already_started"}

        if vt_status == "failed":
            return fail_task(db, task_id, "VirusTotal analysis failed")

        report_ready = bool(vt_report_path and Path(vt_report_path).is_file())
        if vt_status is True and not report_ready:
            return fail_task(db, task_id, "VirusTotal report file not found")

        if not report_ready:
            vt_report_path = vt_report_path or str(REPORTS_DIR / f"virustotal-{md5}.json")
            result = handle_virustotal(
                file_path,
                md5,
                sha256,
                total_size,
                is_retry=self.request.retries > 0,
                report_path=vt_report_path,
            )
            vt_status = result.get("status")
            vt_report_path = result.get("report_path", vt_report_path)
            if vt_status == "pending":
                try:
                    raise self.retry(
                        countdown=result.get("retry_in", 60),
                        kwargs={
                            "vt_status": vt_status,
                            "vt_report_path": vt_report_path,
                        },
                    )
                except MaxRetriesExceededError:
                    return fail_task(db, task_id, "VirusTotal polling exhausted")
            if vt_status is not True:
                return fail_task(db, task_id, result.get("error", "VirusTotal analysis failed"))

        if not Path(vt_report_path).is_file():
            return fail_task(db, task_id, "VirusTotal report file not found")

        report, scores = finalize_analysis_report(
            db, task_id, file_path, vt_report_path, tools="virustotal"
        )
        db.commit()
        return {
            "success": True,
            "task_id": task_id,
            **scores,
            "virustotal_status": True,
            "virustotal_report_path": vt_report_path,
        }
    except Retry:
        raise
    except Exception as error:
        return fail_task(db, task_id, error)
    finally:
        db.close()
