import hashlib
import os
import re
import shutil
import uuid
from pathlib import Path
from tempfile import NamedTemporaryFile

from fastapi import HTTPException, UploadFile, status
from fastapi.concurrency import run_in_threadpool

from bgProcessing.tasks import analyze_malware_task
from cores.Schema.schema_class import User
from cores.async_pg_db import SessionLocal
from services.analy.analy_service import (
    acquire_analysis_hash_lock,
    acquire_analysis_task_lock,
    attempt_gap_fill_redispatch,
    get_file_by_hash,
    get_file_by_task_id,
    insert_table_analy,
    update_analysis_rows_by_task_id,
)
from utils.uuid import parse_uuid


UPLOAD_DIR = Path("temps_files")
REPORTS_DIR = Path("reports")
RESULTS_DIR = Path("results")

for directory in [UPLOAD_DIR, REPORTS_DIR, RESULTS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 1024 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024
REUSABLE_STATUSES = {"queued", "processing", "analyzing", "success"}


def upload_response(filename, md5, sha256, task_id, task_status, deduplicated, queue_state):
    return {
        "success": True,
        "task_id": task_id,
        "status": task_status,
        "md5": md5,
        "sha256": sha256,
        "filename": filename,
        "deduplicated": deduplicated,
        "queue_state": queue_state,
    }


async def scan_file_controller(file: UploadFile, user_id: str, is_private: bool):
    try:
        user_id = parse_uuid(user_id)
    except (TypeError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user identifier.")
    temp_file_path = None
    async with SessionLocal() as db_session:
        user_record = await db_session.get(User, user_id)
        if not user_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"success": False, "code": "USER_NOT_FOUND", "message": "User not found."},
            )
        # Source of truth for the ban check is `is_banned`, not the legacy
        # `status` string - re-checked fresh from the DB on every upload so
        # a user banned mid-session can never sneak one more file through
        # (OWASP A01/A07). Error shape kept identical to before this
        # change (USER_NOT_ACTIVE) so the frontend's existing handling of
        # this specific endpoint doesn't need to change.
        if user_record.is_banned:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"success": False, "code": "USER_NOT_ACTIVE", "message": "User is not active."},
            )

        original_filename = Path(file.filename or "upload").name
        suffix = Path(original_filename).suffix.lower()
        file_extension = suffix if re.fullmatch(r"\.[a-z0-9]{1,10}", suffix) else ""
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        accumulated_size = 0

        try:
            with NamedTemporaryFile(delete=False, dir=UPLOAD_DIR, prefix="upload_", suffix=".tmp") as temp_file:
                temp_file_path = Path(temp_file.name)
                while chunk := await file.read(CHUNK_SIZE):
                    accumulated_size += len(chunk)
                    if accumulated_size > MAX_FILE_SIZE:
                        raise HTTPException(
                            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                            detail="File size exceeds the permitted limit.",
                        )
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
                    temp_file.write(chunk)

            if accumulated_size == 0:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is empty.")

            final_md5 = md5_hash.hexdigest()
            final_sha256 = sha256_hash.hexdigest()

            # Gap-fill takes precedence over plain reuse: if the most
            # recent analysis for this hash finished "success" but had
            # one or more tools force-skipped after exhausting their
            # retry budget (non-null tool_notes), re-dispatch a fresh
            # task that only retries the gap instead of silently
            # returning the same permanently-incomplete result forever.
            # Naturally falls through to "none" for a "dispatching" row
            # (still in-flight - the dispatching-conflict check below
            # still applies) or a "success" row with no tool_notes
            # (nothing to gap-fill), leaving the reusable-attach logic
            # below unchanged for those cases. The freshly-uploaded temp
            # file is unused here (gap-fill reuses the OLD analysis's
            # already-stored file_path) and is cleaned up by the
            # `finally` block below since temp_file_path is left set.
            gap_outcome, gap_analysis = await attempt_gap_fill_redispatch(
                db_session,
                uid=user_id,
                file_hash=final_sha256,
                file_name=original_filename,
                file_size=accumulated_size,
                privacy=is_private,
            )
            if gap_outcome == "gap_filled" and gap_analysis is not None:
                return upload_response(
                    original_filename,
                    final_md5,
                    final_sha256,
                    gap_analysis.task_id,
                    gap_analysis.status,
                    False,
                    "gap_filled",
                )

            await acquire_analysis_hash_lock(db_session, final_sha256)
            existing = await get_file_by_hash(db_session, final_sha256)
            existing_status = existing.get("status") if existing else None
            existing_task_id = existing.get("task_id") if existing else None

            if existing and existing_status == "dispatching" and existing_task_id:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Analysis dispatch is in progress. Retry shortly.",
                )

            if existing and existing_status in REUSABLE_STATUSES and existing_task_id:
                await acquire_analysis_task_lock(db_session, existing_task_id)
                existing = await get_file_by_task_id(db_session, existing_task_id)
                existing_status = existing.get("status") if existing else None
                if not existing or existing_status == "failed":
                    existing = None
                else:
                    await insert_table_analy(
                        session=db_session,
                        uid=user_id,
                        rid=existing.get("rid"),
                        task_id=existing_task_id,
                        tools=existing.get("tools"),
                        status=existing_status,
                        file_name=original_filename,
                        file_hash=final_sha256,
                        file_path=existing.get("file_path"),
                        file_type=existing.get("file_type"),
                        file_size=existing.get("file_size"),
                        privacy=is_private,
                        md5=final_md5,
                    )
                    return upload_response(
                        original_filename,
                        final_md5,
                        final_sha256,
                        existing_task_id,
                        existing_status,
                        True,
                        "reused",
                    )

            target_file_path = UPLOAD_DIR / f"{final_sha256}{file_extension}"
            if target_file_path.exists():
                temp_file_path.unlink()
            else:
                shutil.move(str(temp_file_path), str(target_file_path))
            temp_file_path = None
            task_id = str(uuid.uuid4())
            analysis = await insert_table_analy(
                session=db_session,
                uid=user_id,
                task_id=task_id,
                status="dispatching",
                file_name=original_filename,
                file_hash=final_sha256,
                file_path=str(target_file_path),
                file_type=file_extension.lstrip("."),
                file_size=accumulated_size,
                privacy=is_private,
                md5=final_md5,
            )

            try:
                await run_in_threadpool(
                    analyze_malware_task.apply_async,
                    args=(str(target_file_path), final_md5, final_sha256, accumulated_size),
                    task_id=task_id,
                )
            except Exception:
                await acquire_analysis_hash_lock(db_session, final_sha256)
                await update_analysis_rows_by_task_id(
                    db_session,
                    analysis.task_id,
                    status="failed",
                    from_statuses=("dispatching",),
                )
                await db_session.commit()
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Analysis queue is unavailable.",
                )

            await acquire_analysis_hash_lock(db_session, final_sha256)
            await update_analysis_rows_by_task_id(
                db_session,
                analysis.task_id,
                status="queued",
                from_statuses=("dispatching",),
            )
            await db_session.commit()

            return upload_response(
                original_filename,
                final_md5,
                final_sha256,
                task_id,
                "queued",
                False,
                "dispatched",
            )
        except HTTPException:
            raise
        except Exception:
            await db_session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An internal server error occurred while processing the file.",
            )
        finally:
            if temp_file_path and temp_file_path.exists():
                temp_file_path.unlink()
