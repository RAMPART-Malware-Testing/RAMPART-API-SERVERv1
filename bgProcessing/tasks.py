import json
from pathlib import Path
from datetime import datetime, timezone

from celery.exceptions import MaxRetriesExceededError, Retry
from sqlalchemy import select, text, update

from bgProcessing.celery_app import celery_app
from bgProcessing.report_evidence import build_gemini_evidence
from bgProcessing.task_utils import apply_gemini_assessment
from bgProcessing.task_handlers import (
    calculate_cape_danger_score,
    calculate_mobsf_danger_score,
    calculate_rampart_ai_score,
    calculate_threat_scoreVT,
    get_malicious_virustotal_results,
    handle_cape,
    handle_mobsf,
    handle_rampart_ai,
    handle_virustotal,
    write_raw_virustotal_report,
)
from cores.Schema.schema_class import Analysis, Reports
from cores.sync_pg_db import SyncSessionLocal
from cores.redis import redis_client
from calling.GeminiAPI import GeminiAPI
from bgProcessing.notifications import notify_analysis_failed, notify_analysis_success

REPORTS_DIR = Path("reports")
ACTIVE_STATUSES = ("dispatching", "queued", "processing")
FINALIZABLE_STATUSES = ("processing", "success")
PROGRESS_TTL_SECONDS = 86400

MAX_TOOL_ERROR_RETRIES = 3
MAX_TOOL_POLL_ATTEMPTS = 10
MAX_CAPE_POLL_ATTEMPTS = 40

TOOL_LABELS = {"virustotal": "VirusTotal", "mobsf": "MobSF", "cape": "CAPE"}

class TaskFinalizationError(RuntimeError):
    pass

def publish_progress(task_id: str, stage: str, message: str, **values) -> None:
    payload = {
        "stage": stage,
        "message": message,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        **values,
    }
    try:
        redis_client.setex(
            f"analysis_progress:{task_id}",
            PROGRESS_TTL_SECONDS,
            json.dumps(payload, ensure_ascii=False),
        )
    except Exception as error:
        print(f"[Progress] Unable to publish task {task_id}: {error}")

def update_task_rows(db, task_id: str, status: str, from_statuses: tuple[str, ...], **values) -> int:
    statement = update(Analysis).where(
        Analysis.task_id == task_id,
        Analysis.status.in_(from_statuses),
    )
    result = db.execute(statement.values(status=status, **values))
    return result.rowcount

def fail_task(db, task_id: str, error, *, report_paths=(), tool_notes: dict | None = None) -> dict:
    message = str(error)
    publish_progress(task_id, "failed", message, error=message, tool_notes=tool_notes or None)
    for report_path in report_paths:
        if not report_path:
            continue
        try:
            Path(report_path).unlink(missing_ok=True)
        except OSError as cleanup_error:
            print(f"[Analysis] Failed to remove report {report_path}: {cleanup_error}")
    db.rollback()
    update_task_rows(
        db,
        task_id,
        "failed",
        ACTIVE_STATUSES,
        tool_notes=json.dumps(tool_notes, ensure_ascii=False) if tool_notes else None,
    )
    db.commit()
    try:
        notify_analysis_failed(db, task_id, message)
    except Exception as notify_error:
        print(f"[Notify] Failed to send failure email for {task_id}: {notify_error}")
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

def evaluate_tool_progress(
    *,
    tool_key: str,
    result: dict,
    attempts: int,
    polls: int,
    max_attempts: int = MAX_TOOL_ERROR_RETRIES,
    max_polls: int = MAX_TOOL_POLL_ATTEMPTS,
) -> dict:
    """Normalizes one pass of a VirusTotal/MobSF/CAPE handler result into
    the shared retry-then-skip policy, so all three tools are handled by
    one piece of logic instead of three near-duplicated blocks.

    `result["status"]` from the handler can be:
      - True         -> terminal success, passed straight through.
      - "skipped"    -> terminal soft-skip decided by the handler itself
                        (e.g. unsupported file type) - passed straight
                        through with no note (this is a normal, expected
                        outcome, not a degraded one).
      - "pending"    -> the tool is legitimately still working. Counted
                        against `max_polls`; once exceeded, force-skipped
                        with a note.
      - anything else (including "failed") -> treated as a retryable
                        error. Counted against `max_attempts`; once
                        exceeded, force-skipped with a note. Below the
                        cap, reported back as "pending" so the caller's
                        retry machinery is identical for both polling and
                        error-backoff waits.

    Returns a dict: {status, attempts, polls, retry_countdown, note}.
    `retry_countdown` is only meaningful when status == "pending" (the
    caller still needs another Celery retry pass). `note` is only set
    when this call just force-skipped the tool.
    """
    label = TOOL_LABELS.get(tool_key, tool_key)
    status = result.get("status")

    if status is True or status == "skipped":
        return {"status": status, "attempts": attempts, "polls": polls, "retry_countdown": None, "note": None}

    if status == "pending":
        polls += 1
        if polls > max_polls:
            note = f"{label} skipped after {max_polls} status checks with no result"
            print(f"[{label}] {note}")
            return {"status": "skipped", "attempts": attempts, "polls": polls, "retry_countdown": None, "note": note}
        return {
            "status": "pending",
            "attempts": attempts,
            "polls": polls,
            "retry_countdown": result.get("retry_in", 30),
            "note": None,
        }

    attempts += 1
    error = str(result.get("error", f"{label} analysis failed"))
    if attempts >= max_attempts:
        note = f"{label} skipped after {max_attempts} failed attempts: {error}"
        print(f"[{label}] {note}")
        return {"status": "skipped", "attempts": attempts, "polls": polls, "retry_countdown": None, "note": note}
    print(f"[{label}] Attempt {attempts}/{max_attempts} failed, will retry: {error}")
    return {
        "status": "pending",
        "attempts": attempts,
        "polls": polls,
        "retry_countdown": 30 * attempts,
        "note": None,
    }

def finalize_analysis_report(
    db,
    task_id: str,
    file_path: str,
    vt_report_path: str | None,
    *,
    mobsf_report_path: str | None = None,
    cape_report_path: str | None = None,
    rampart_ai_report_path: str | None = None,
    tools: str = "virustotal",
    tool_notes: dict | None = None,
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

        if vt_report_path:
            vt_report = read_report(vt_report_path)
            virustotal_score = calculate_threat_scoreVT(vt_report)
            signatures, malicious = virustotal_report_values(vt_report)
            del vt_report
        else:
            virustotal_score = None
            signatures, malicious = [], False
        scores = {
            "virustotal_score": virustotal_score,
            "mobsf_score": read_sandbox_score(mobsf_report_path, calculate_mobsf_danger_score),
            "cape_score": read_sandbox_score(cape_report_path, calculate_cape_danger_score),
            "rampart_ai_score": read_sandbox_score(rampart_ai_report_path, calculate_rampart_ai_score),
        }
        rampartai_prediction = None
        if rampart_ai_report_path:
            try:
                if Path(rampart_ai_report_path).is_file():
                    rampartai_prediction = read_report(rampart_ai_report_path)
            except Exception:
                rampartai_prediction = None
        if report_ids:
            report = db.get(Reports, next(iter(report_ids)))
            if report is None:
                raise TaskFinalizationError("Associated report not found")
            report.virustotal_score = scores["virustotal_score"]
            report.mobsf_score = scores["mobsf_score"]
            report.cape_score = scores["cape_score"]
            report.rampart_ai_score = rampartai_prediction
            report.malware_signatures = signatures
        else:
            report = Reports(
                file_type=Path(file_path).suffix.lstrip(".") or None,
                virustotal_score=scores["virustotal_score"],
                mobsf_score=scores["mobsf_score"],
                cape_score=scores["cape_score"],
                rampart_ai_score=rampartai_prediction,
                malware_signatures=signatures,
            )
            db.add(report)
            db.flush()

        values = {
            "status": "success",
            "rid": report.rid,
            "tools": tools,
            "tool_notes": json.dumps(tool_notes, ensure_ascii=False) if tool_notes else None,
        }
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

@celery_app.task(bind=True, max_retries=60)
def analyze_malware_task(
    self,
    file_path: str,
    md5: str,
    sha256: str,
    total_size: int,
    vt_status=None,
    vt_report_path: str | None = None,
    vt_submitted: bool = False,
    vt_attempts: int = 0,
    vt_polls: int = 0,
    mobsf_status=None,
    mobsf_report_path: str | None = None,
    mobsf_submitted: bool = False,
    mobsf_attempts: int = 0,
    mobsf_polls: int = 0,
    cape_status=None,
    cape_report_path: str | None = None,
    cape_task_id=None,
    cape_attempts: int = 0,
    cape_polls: int = 0,
    rampart_ai_status=None,
    rampart_ai_report_path: str | None = None,
    gemini_status=None,
    tool_notes: dict | None = None,
):
    db = SyncSessionLocal()
    task_id = self.request.id
    tool_notes = dict(tool_notes) if tool_notes else {}

    try:
        publish_progress(task_id, "worker", "Celery worker accepted the task")
        started = update_task_rows(db, task_id, "processing", ("dispatching", "queued"))
        db.commit()
        if not started and (
            task_is_complete(db, task_id)
            or self.request.retries == 0 and not any((vt_report_path, mobsf_report_path, cape_report_path, mobsf_submitted, cape_task_id))
        ):
            return {"success": True, "task_id": task_id, "state": "already_started"}

        if vt_status is True:
            if not (vt_report_path and Path(vt_report_path).is_file()):
                return fail_task(db, task_id, "VirusTotal report file not found", tool_notes=tool_notes)

        if vt_status not in (True, "skipped"):
            publish_progress(task_id, "virustotal", "Checking VirusTotal report")
            vt_report_path = vt_report_path or str(REPORTS_DIR / f"virustotal-{md5}.json")
            result = handle_virustotal(
                file_path,
                md5,
                sha256,
                total_size,
                is_retry=vt_submitted,
                report_path=vt_report_path,
            )
            if result.get("status") is True:
                vt_report_path = result.get("report_path", vt_report_path)
            vt_submitted = True
            outcome = evaluate_tool_progress(tool_key="virustotal", result=result, attempts=vt_attempts, polls=vt_polls)
            vt_attempts, vt_polls = outcome["attempts"], outcome["polls"]
            vt_status = outcome["status"]
            if outcome["note"]:
                tool_notes["virustotal"] = outcome["note"]

            if vt_status == "pending":
                publish_progress(
                    task_id,
                    "virustotal",
                    "VirusTotal report is pending",
                    tools={"virustotal": {"status": "pending"}},
                )
                try:
                    raise self.retry(
                        countdown=outcome["retry_countdown"],
                        kwargs={
                            "vt_status": vt_status,
                            "vt_report_path": vt_report_path,
                            "vt_submitted": vt_submitted,
                            "vt_attempts": vt_attempts,
                            "vt_polls": vt_polls,
                            "tool_notes": tool_notes,
                        },
                    )
                except MaxRetriesExceededError:
                    return fail_task(
                        db, task_id, "VirusTotal polling exhausted",
                        report_paths=(vt_report_path,), tool_notes=tool_notes,
                    )

        vt_score = None
        if vt_status is True:
            if not Path(vt_report_path).is_file():
                return fail_task(db, task_id, "VirusTotal report file not found", tool_notes=tool_notes)
            vt_score = calculate_threat_scoreVT(vt_report_path)
            publish_progress(
                task_id,
                "virustotal",
                "VirusTotal analysis completed",
                tools={"virustotal": {"status": "success", "score": vt_score}},
            )
            if vt_score == 100:
                try:
                    evidence = build_gemini_evidence(vt_report_path, None, None)
                except Exception as error:
                    print(f"[Gemini] Evidence build failed for {file_path}: {error}")
                    evidence = None
                publish_progress(
                    task_id,
                    "gemini",
                    "Gemini is synthesizing tool evidence",
                    tools={
                        "virustotal": {"status": "success", "score": vt_score},
                        "mobsf": {"status": "skipped", "note": "Skipped: VirusTotal already detected malware"},
                        "cape": {"status": "skipped", "note": "Skipped: VirusTotal already detected malware"},
                        "rampart_ai": {"status": "skipped", "note": "Skipped: VirusTotal already detected malware"},
                        "gemini": {"status": "processing"},
                    },
                )
                try:
                    assessment = GeminiAPI().AnalysisGemini(evidence) if evidence else {}
                except Exception as error:
                    print(f"[Gemini] Analysis failed for {file_path}: {error}")
                    assessment = {}
                tools = "virustotal,gemini" if assessment else "virustotal"
                report, scores = finalize_analysis_report(
                    db, task_id, file_path, vt_report_path, tools=tools, tool_notes=tool_notes or None
                )
                if assessment:
                    apply_gemini_assessment(report, assessment)
                db.commit()
                try:
                    notify_analysis_success(db, task_id)
                except Exception as notify_error:
                    print(f"[Notify] Failed to send success email for {task_id}: {notify_error}")
                return {
                    "success": True,
                    "task_id": task_id,
                    **scores,
                    "virustotal_status": True,
                    "virustotal_report_path": vt_report_path,
                }
        else:
            publish_progress(
                task_id,
                "virustotal",
                "VirusTotal skipped",
                tools={"virustotal": {"status": "skipped", "note": tool_notes.get("virustotal")}},
            )

        mobsf_ready = bool(mobsf_status is True and mobsf_report_path and Path(mobsf_report_path).is_file())
        mobsf_countdown = None
        if mobsf_status not in (True, "skipped") and not mobsf_ready:
            publish_progress(task_id, "sandboxes", "Advancing MobSF analysis")
            mobsf_report_path = mobsf_report_path or str(REPORTS_DIR / f"mobsf-{md5}.json")
            result = handle_mobsf(
                file_path,
                md5,
                submitted=mobsf_submitted,
                report_path=mobsf_report_path,
            )
            if result.get("status") is True:
                mobsf_report_path = result.get("report_path", mobsf_report_path)
            mobsf_submitted = bool(result.get("submitted", mobsf_submitted))
            outcome = evaluate_tool_progress(tool_key="mobsf", result=result, attempts=mobsf_attempts, polls=mobsf_polls)
            mobsf_attempts, mobsf_polls = outcome["attempts"], outcome["polls"]
            mobsf_status = outcome["status"]
            mobsf_countdown = outcome["retry_countdown"]
            if outcome["note"]:
                tool_notes["mobsf"] = outcome["note"]

        rampart_ai_ready = rampart_ai_status in (True, "skipped") and (
            rampart_ai_status != True or bool(rampart_ai_report_path and Path(rampart_ai_report_path).is_file())
        )
        if mobsf_status in (True, "skipped") and not rampart_ai_ready:
            if mobsf_status is True:
                publish_progress(
                    task_id,
                    "rampart_ai",
                    "Classifying MobSF report with RampartAI",
                    tools={
                        "virustotal": {"status": vt_status if vt_status is True else "skipped", "score": vt_score},
                        "mobsf": {"status": mobsf_status},
                        "cape": {"status": cape_status or "pending"},
                        "rampart_ai": {"status": "processing"},
                    },
                )
                rampart_ai_report_path = rampart_ai_report_path or str(REPORTS_DIR / f"rampartai-{md5}.json")
                rai_result = handle_rampart_ai(
                    mobsf_report_path,
                    md5,
                    report_path=rampart_ai_report_path,
                )
                rampart_ai_status = rai_result.get("status")
                rampart_ai_report_path = rai_result.get("report_path", rampart_ai_report_path)
            else:
                rampart_ai_status = "skipped"

        cape_ready = bool(cape_status is True and cape_report_path and Path(cape_report_path).is_file())
        cape_countdown = None
        if cape_status not in (True, "skipped") and not cape_ready:
            publish_progress(
                task_id,
                "sandboxes",
                "Advancing CAPE analysis",
                tools={
                    "virustotal": {"status": vt_status if vt_status is True else "skipped", "score": vt_score},
                    "mobsf": {"status": mobsf_status},
                    "cape": {"status": "processing", "task_id": cape_task_id},
                    "rampart_ai": {"status": rampart_ai_status or "waiting"},
                },
            )
            cape_report_path = cape_report_path or str(REPORTS_DIR / f"cape-{md5}.json")
            result = handle_cape(
                file_path,
                md5,
                task_id=cape_task_id,
                report_path=cape_report_path,
            )
            if result.get("status") is True:
                cape_report_path = result.get("report_path", cape_report_path)
            cape_task_id = result.get("task_id", cape_task_id)
            outcome = evaluate_tool_progress(
                tool_key="cape", result=result, attempts=cape_attempts, polls=cape_polls,
                max_polls=MAX_CAPE_POLL_ATTEMPTS,
            )
            cape_attempts, cape_polls = outcome["attempts"], outcome["polls"]
            cape_status = outcome["status"]
            cape_countdown = outcome["retry_countdown"]
            if outcome["note"]:
                tool_notes["cape"] = outcome["note"]
            publish_progress(
                task_id,
                "sandboxes",
                "CAPE analysis updated",
                tools={
                    "virustotal": {"status": vt_status if vt_status is True else "skipped", "score": vt_score},
                    "mobsf": {"status": mobsf_status},
                    "cape": {"status": cape_status, "task_id": cape_task_id, "note": tool_notes.get("cape")},
                    "rampart_ai": {"status": rampart_ai_status or "waiting"},
                },
            )

        pending_countdowns = [
            countdown
            for status, countdown in ((mobsf_status, mobsf_countdown), (cape_status, cape_countdown))
            if status == "pending" and countdown is not None
        ]
        if mobsf_status == "pending" or cape_status == "pending":
            publish_progress(
                task_id,
                "sandboxes",
                "Waiting for sandbox reports",
                tools={
                    "virustotal": {"status": vt_status if vt_status is True else "skipped", "score": vt_score},
                    "mobsf": {"status": mobsf_status, "note": tool_notes.get("mobsf")},
                    "cape": {"status": cape_status, "task_id": cape_task_id, "note": tool_notes.get("cape")},
                    "rampart_ai": {"status": rampart_ai_status or "waiting"},
                    "gemini": {"status": "waiting"},
                },
            )
            try:
                raise self.retry(
                    countdown=min(pending_countdowns) if pending_countdowns else 30,
                    kwargs={
                        "vt_status": True,
                        "vt_report_path": vt_report_path,
                        "vt_submitted": vt_submitted,
                        "mobsf_status": mobsf_status,
                        "mobsf_report_path": mobsf_report_path,
                        "mobsf_submitted": mobsf_submitted,
                        "mobsf_attempts": mobsf_attempts,
                        "mobsf_polls": mobsf_polls,
                        "cape_status": cape_status,
                        "cape_report_path": cape_report_path,
                        "cape_task_id": cape_task_id,
                        "cape_attempts": cape_attempts,
                        "cape_polls": cape_polls,
                        "rampart_ai_status": rampart_ai_status,
                        "rampart_ai_report_path": rampart_ai_report_path,
                        "tool_notes": tool_notes,
                    },
                )
            except MaxRetriesExceededError:
                print(f"[Analysis] Sandbox polling exhausted for {file_path}")
                return fail_task(
                    db, task_id, "Sandbox polling exhausted",
                    report_paths=(), tool_notes=tool_notes,
                )

        successful_tools = []
        successful_mobsf_path = None
        successful_cape_path = None
        if vt_status is True:
            successful_tools.append("virustotal")
        if mobsf_status is True:
            successful_tools.append("mobsf")
            successful_mobsf_path = mobsf_report_path
        if cape_status is True:
            successful_tools.append("cape")
            successful_cape_path = cape_report_path

        successful_rampart_ai_path = rampart_ai_report_path if rampart_ai_status is True else None
        if rampart_ai_status is True:
            successful_tools.append("rampart_ai")

        evidence = build_gemini_evidence(
            vt_report_path if vt_status is True else None,
            successful_mobsf_path,
            successful_cape_path,
        )
        publish_progress(
            task_id,
            "gemini",
            "Gemini is synthesizing tool evidence",
            tools={
                "virustotal": {"status": vt_status if vt_status is True else "skipped", "score": vt_score},
                "mobsf": {"status": mobsf_status, "note": tool_notes.get("mobsf")},
                "cape": {"status": cape_status, "task_id": cape_task_id, "note": tool_notes.get("cape")},
                "rampart_ai": {"status": rampart_ai_status},
                "gemini": {"status": "processing"},
            },
        )
        try:
            assessment = GeminiAPI().AnalysisGemini(evidence)
        except Exception as error:
            print(f"[Gemini] Analysis failed for {file_path}: {error}")
            publish_progress(
                task_id,
                "gemini",
                "Gemini analysis failed, retrying",
                tools={
                    "virustotal": {"status": vt_status if vt_status is True else "skipped", "score": vt_score},
                    "mobsf": {"status": mobsf_status, "note": tool_notes.get("mobsf")},
                    "cape": {"status": cape_status, "task_id": cape_task_id, "note": tool_notes.get("cape")},
                    "rampart_ai": {"status": rampart_ai_status},
                    "gemini": {"status": "pending"},
                },
            )
            try:
                raise self.retry(
                    countdown=60,
                    kwargs={
                        "vt_status": True if vt_status is True else "skipped",
                        "vt_report_path": vt_report_path,
                        "vt_submitted": vt_submitted,
                        "mobsf_status": mobsf_status,
                        "mobsf_report_path": successful_mobsf_path,
                        "mobsf_submitted": mobsf_submitted,
                        "mobsf_attempts": mobsf_attempts,
                        "mobsf_polls": mobsf_polls,
                        "cape_status": cape_status,
                        "cape_report_path": successful_cape_path,
                        "cape_task_id": cape_task_id,
                        "cape_attempts": cape_attempts,
                        "cape_polls": cape_polls,
                        "rampart_ai_status": rampart_ai_status,
                        "rampart_ai_report_path": successful_rampart_ai_path,
                        "gemini_status": "pending",
                        "tool_notes": tool_notes,
                    },
                )
            except MaxRetriesExceededError:
                return fail_task(db, task_id, "Gemini analysis exhausted retries", tool_notes=tool_notes)
        successful_tools.append("gemini")
        report, scores = finalize_analysis_report(
            db,
            task_id,
            file_path,
            vt_report_path if vt_status is True else None,
            mobsf_report_path=successful_mobsf_path,
            cape_report_path=successful_cape_path,
            rampart_ai_report_path=successful_rampart_ai_path,
            tools=",".join(successful_tools),
            tool_notes=tool_notes or None,
        )
        apply_gemini_assessment(report, assessment)
        db.commit()
        try:
            notify_analysis_success(db, task_id)
        except Exception as notify_error:
            print(f"[Notify] Failed to send success email for {task_id}: {notify_error}")
        publish_progress(
            task_id,
            "complete",
            "Analysis and database commit completed",
            tools={
                "virustotal": {"status": vt_status if vt_status is True else "skipped", "score": scores["virustotal_score"]},
                "mobsf": {"status": mobsf_status, "score": scores["mobsf_score"], "note": tool_notes.get("mobsf")},
                "cape": {"status": cape_status, "score": scores["cape_score"], "task_id": cape_task_id, "note": tool_notes.get("cape")},
                "rampart_ai": {"status": rampart_ai_status, "score": scores["rampart_ai_score"]},
                "gemini": {"status": "success", "score": assessment["danger_score"]},
            },
            tool_notes=tool_notes or None,
        )
        return {
            "success": True,
            "task_id": task_id,
            **scores,
            "virustotal_status": vt_status,
            "virustotal_report_path": vt_report_path if vt_status is True else None,
            "mobsf_status": mobsf_status,
            "mobsf_report_path": successful_mobsf_path,
            "cape_status": cape_status,
            "cape_report_path": successful_cape_path,
            "cape_task_id": cape_task_id,
            "rampart_ai_status": rampart_ai_status,
            "rampart_ai_report_path": successful_rampart_ai_path,
            "gemini_assessment": assessment,
            "tool_notes": tool_notes or None,
        }
    except Retry:
        raise
    except Exception as error:
        return fail_task(db, task_id, error, tool_notes=tool_notes)
    finally:
        db.close()
