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
    attempt_attach_to_existing_analysis,
    attempt_gap_fill_redispatch,
    build_carry_forward_kwargs,
    carry_forward_states,
    completeness_summary,
    evaluate_tool_completeness,
    get_content_row_for_recovery,
    update_analysis_rows_by_task_id,
    upsert_user_analysis,
)
from services.dashboard.dashboars_service import invalidate_public_caches
from utils.uuid import parse_uuid

UPLOAD_DIR = Path("temps_files")
REPORTS_DIR = Path("reports")
RESULTS_DIR = Path("results")

for directory in [UPLOAD_DIR, REPORTS_DIR, RESULTS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 1024 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024

def upload_response(filename, md5, sha256, task_id, task_status, deduplicated, queue_state, completeness=None):
    response = {
        "success": True,
        "task_id": task_id,
        "status": task_status,
        "md5": md5,
        "sha256": sha256,
        "filename": filename,
        "deduplicated": deduplicated,
        "queue_state": queue_state,
    }
    if completeness is not None:
        response["completeness"] = completeness
    return response

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

            gap_outcome, gap_analysis = await attempt_gap_fill_redispatch(
                db_session,
                uid=user_id,
                file_hash=final_sha256,
                file_name=original_filename,
                file_size=accumulated_size,
                privacy=is_private,
            )
            if gap_outcome == "gap_filled" and gap_analysis is not None:
                invalidate_public_caches()
                return upload_response(
                    original_filename,
                    final_md5,
                    final_sha256,
                    gap_analysis.task_id,
                    gap_analysis.status,
                    False,
                    "gap_filled",
                    completeness_summary(gap_analysis),
                )

            attach_outcome, attached = await attempt_attach_to_existing_analysis(
                db_session,
                uid=user_id,
                file_hash=final_sha256,
                file_name=original_filename,
                file_size=accumulated_size,
                privacy=is_private,
            )
            if attach_outcome == "dispatching":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Analysis dispatch is in progress. Retry shortly.",
                )
            if attach_outcome == "attached" and attached is not None:
                invalidate_public_caches()
                return upload_response(
                    original_filename,
                    final_md5,
                    final_sha256,
                    attached.task_id,
                    attached.status,
                    True,
                    "reused" if attached.status == "success" else "waiting",
                    completeness_summary(attached),
                )
                invalidate_public_caches()

            target_file_path = UPLOAD_DIR / f"{final_sha256}{file_extension}"
            if target_file_path.exists():
                temp_file_path.unlink()
            else:
                shutil.move(str(temp_file_path), str(target_file_path))
            temp_file_path = None
            recovery_row = await get_content_row_for_recovery(db_session, final_sha256)
            carry_forward_kwargs = {}
            recovery_rid = None
            if recovery_row is not None:
                recovery_rid = recovery_row.get("rid")
                carry_forward_kwargs, _ = build_carry_forward_kwargs(
                    recovery_row, evaluate_tool_completeness(recovery_row)
                )
                recovery_states = carry_forward_states(recovery_row)
                if recovery_states:
                    carry_forward_kwargs["tool_states"] = recovery_states
            task_id = str(uuid.uuid4())
            analysis = await upsert_user_analysis(
                session=db_session,
                uid=user_id,
                rid=recovery_rid,
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
                    kwargs=carry_forward_kwargs or None,
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
            invalidate_public_caches()

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
