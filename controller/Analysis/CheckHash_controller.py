"""Hash-only pre-upload dedup check.

The frontend computes the sha256 of a file locally (Web Crypto API) before
ever sending any bytes to the server. If that content hash has already been
analyzed (or is currently being analyzed), we attach the caller to the
existing task and hand back its current status/report immediately - no
upload, no re-analysis. Only on a genuine cache miss does the client fall
back to the full upload flow.
"""

import re

from fastapi import HTTPException, status

from cores.async_pg_db import SessionLocal
from cores.Schema.schema_class import User
from services.analy.analy_service import (
    attempt_attach_to_existing_analysis,
    attempt_gap_fill_redispatch,
    get_analysis_with_report,
)
from utils.uuid import parse_uuid

_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


async def check_hash_controller(user_id: str, sha256: str, file_name: str, file_size: int, is_private: bool):
    if not _SHA256_RE.match(sha256 or ""):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid sha256 hash.")

    try:
        user_id = parse_uuid(user_id)
    except (TypeError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user identifier.")

    async with SessionLocal() as db_session:
        user_record = await db_session.get(User, user_id)
        if not user_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"success": False, "code": "USER_NOT_FOUND", "message": "User not found."},
            )
        if user_record.status.lower() != "active":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"success": False, "code": "USER_NOT_ACTIVE", "message": "User is not active."},
            )

        try:
            # Gap-fill takes precedence over plain reuse: if the most
            # recent analysis for this hash finished "success" but had
            # one or more tools force-skipped after exhausting their
            # retry budget (non-null tool_notes), re-dispatch a fresh
            # task that only retries the gap instead of silently handing
            # back the same permanently-incomplete result forever. This
            # naturally falls through to "none" for a "dispatching" row
            # (still in-flight, not "success" yet) or a "success" row
            # with no tool_notes (nothing to gap-fill), letting the
            # existing attach logic below handle those cases unchanged.
            outcome, analysis = await attempt_gap_fill_redispatch(
                db_session,
                uid=user_id,
                file_hash=sha256.lower(),
                file_name=file_name,
                file_size=file_size,
                privacy=is_private,
            )
            if outcome == "none":
                outcome, analysis = await attempt_attach_to_existing_analysis(
                    db_session,
                    uid=user_id,
                    file_hash=sha256.lower(),
                    file_name=file_name,
                    file_size=file_size,
                    privacy=is_private,
                )
        except Exception:
            await db_session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An internal server error occurred while checking the file hash.",
            )

        if outcome == "dispatching":
            return {
                "success": True,
                "found": False,
                "status": "dispatching",
                "message": "Analysis dispatch is in progress for this file. Please upload as normal.",
            }

        if outcome == "gap_filled" and analysis is not None:
            # Response shape mirrors a fresh-dispatch ("found": True since
            # we DO have a matching hash on record, "status": "queued" for
            # the new task) plus an explicit "gap_filled": True flag so the
            # frontend can distinguish "here's your fully-cached prior
            # result" (outcome == "attached", gap_filled absent/False) from
            # "we're re-running just the piece that was missing"
            # (gap_filled == True, task_id is a brand-new task to poll).
            return {
                "success": True,
                "found": True,
                "gap_filled": True,
                "task_id": analysis.task_id,
                "status": analysis.status,
                "md5": analysis.md5,
                "sha256": analysis.file_hash,
                "filename": analysis.file_name,
                "message": "Prior analysis had gaps; re-running the missing tool(s).",
            }

        if outcome != "attached" or analysis is None:
            return {"success": True, "found": False}

        report = None
        if analysis.status == "success" and analysis.task_id:
            row = await get_analysis_with_report(db_session, analysis.task_id, uid=user_id)
            if row and row[1] is not None:
                report = row[1]

        return {
            "success": True,
            "found": True,
            "task_id": analysis.task_id,
            "status": analysis.status,
            "md5": analysis.md5,
            "sha256": analysis.file_hash,
            "filename": analysis.file_name,
            "report": (
                {
                    "score": float(report.score) if report.score is not None else None,
                    "risk_level": report.risk_level,
                    "virustotal_score": report.virustotal_score,
                    "mobsf_score": float(report.mobsf_score) if report.mobsf_score is not None else None,
                    "cape_score": float(report.cape_score) if report.cape_score is not None else None,
                    "rampart_ai_score": (
                        report.rampart_ai_score if report.rampart_ai_score is not None else None
                    ),
                }
                if report
                else None
            ),
        }
