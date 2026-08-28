from pathlib import Path
import re
import aiofiles
from fastapi import UploadFile, HTTPException
from fastapi.concurrency import run_in_threadpool
from bgProcessing.tasks import analyze_malware_task
from cores.async_pg_db import SessionLocal
from cores.Schema.schema_class import User
from schemas.analy import AnalysisHistoryParams 
from services.admin.admin_service import write_audit_log
from services.admin.authz import ADMIN_ROLES, AuthError, ensure_not_banned, get_current_user
from services.analy.analy_service import get_analysis_history, get_analysis_with_report, get_analysis_with_report_admin, get_file_by_hash, get_public_analysis_with_report, insert_table_analy
from services.token_service import TokenService
import os
from pathlib import Path
from cores.redis import redis_client
from utils.cache import build_suffix, cached_async, invalidate_cached
from utils.calculate_hash import calculate_hash_from_chunks
from utils.jwt import create_token
from utils.uuid import parse_uuid
import json

TASK_STATUS_CACHE_NAMESPACE = "analy:task_status"
TASK_STATUS_CACHE_TTL_SECONDS = 3

UPLOAD_DIR = Path("temps_files")
REPORTS_DIR = Path("reports")
RESULTS_DIR = Path("results")

for directory in [UPLOAD_DIR, REPORTS_DIR, RESULTS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024
VIRUSTOTAL_MAX_SIZE = 32 * 1024 * 1024

BASE_REPORT_PATH = Path("reports").resolve()
FILENAME_REGEX = re.compile(r"^(virustotal|mobsf|cape|rampartai)-([a-fA-F0-9]{32})\.json$")

TOOL_REPORT_PREFIX = {
    "virustotal": "virustotal",
    "mobsf": "mobsf",
    "cape": "cape",
    "rampartai": "rampartai",
}

def decode_redis_data(data):
    if not data:
        return None
    return {k.decode('utf-8'): v.decode('utf-8') for k, v in data.items()}

def _parse_tool_notes(raw: str | None) -> dict | None:
    """Best-effort decode of Analysis.tool_notes (JSON-encoded dict of
    {tool_name: reason}, populated only when a tool was force-skipped
    after exhausting its retry budget - see bgProcessing/tasks.py)."""
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None

def get_file_info_from_redis(sha256_hash):
    try:
        redis_key = f"file:{sha256_hash}"
        raw_data = redis_client.hgetall(redis_key)
        return raw_data
    except Exception as e:
        print(f"Redis error when getting file info: {e}")
        return None

async def require_upload_token(token: str) -> str:
    payload, err = TokenService.verify_token(token, "upload")
    if err:
        raise HTTPException(status_code=401, detail="Invalid upload token")

    try:
        uid = str(parse_uuid(payload.get("sub")))
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid upload token subject")
    session_key = f"upload_session:{uid}"

    try:
        stored_token = await run_in_threadpool(redis_client.get, session_key)
    except Exception:
        raise HTTPException(status_code=503, detail="Upload session service is unavailable.")
    if not stored_token or stored_token != token:
        raise HTTPException(status_code=401, detail="Upload token is invalid or already used")

    return str(uid)

async def generateToken_controller(token):
    async with SessionLocal() as session:
        try:
            user = await get_current_user(session, token)
            ensure_not_banned(user)
        except AuthError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message)
        uid = str(user.uid)
    session_key = f"upload_session:{uid}"

    existing_token = redis_client.get(session_key)
    if existing_token:
        ttl = redis_client.ttl(session_key)
        return {
            "success": True,
            "status": "TOKEN_ALREADY_EXISTS",
            "message": "โทเคนสำหรับอัปโหลดไฟล์ถูกสร้างสำเร็จ",
            "data": {
                "upload_token": existing_token,
                "expires_in": ttl
            }
        }

    upload_token = create_token(
        subject=uid,
        token_type="upload",
        expires_minutes=15 
    )

    UPLOAD_TOKEN_TTL = 60 * 15 
    redis_client.setex(session_key, UPLOAD_TOKEN_TTL, upload_token)

    return {
        "success": True,
        "status": "TOKEN_CREATED",
        "message": "สร้างโทเคนสำหรับอัปโหลดไฟล์สำเร็จ",
        "data": {
            "upload_token": upload_token,
            "expires_in": UPLOAD_TOKEN_TTL
        }
    }

def _read_task_progress(task_id: str) -> dict | None:
    """Best-effort read of the live per-tool progress a running Celery task
    publishes to Redis (see bgProcessing/tasks.py::publish_progress).

    Returns None if unavailable (Redis down, key expired, or nothing
    published yet) - callers must treat that as "no extra detail available"
    rather than an error, since polling status must never hard-fail just
    because the progress side-channel is empty.
    """
    try:
        raw = redis_client.get(f"analysis_progress:{task_id}")
    except Exception:
        return None
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None

async def analysisReport_controller(uid: str, task_id: str):
    suffix = build_suffix(task_id=task_id, uid=uid)
    return await cached_async(
        TASK_STATUS_CACHE_NAMESPACE,
        TASK_STATUS_CACHE_TTL_SECONDS,
        lambda: _compute_analysis_report(uid, task_id),
        suffix=suffix,
    )

async def _compute_analysis_report(uid: str, task_id: str):
    try:
        uid = parse_uuid(uid)
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token payload")
    async with SessionLocal() as session:
        user = await session.get(User, uid)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        if user.is_banned:
            raise HTTPException(status_code=403, detail="Account is banned")
        row = await get_analysis_with_report(session, task_id, uid=uid)
        if not row:
            row = await get_public_analysis_with_report(session, task_id)
        if not row and user.role in ADMIN_ROLES:
            row = await get_analysis_with_report_admin(session, task_id)
            if row:
                await write_audit_log(
                    session,
                    actor_uid=user.uid,
                    target_uid=row[0].uid,
                    action="view_private_analysis",
                    detail=f"task_id={task_id}",
                )
                await session.commit()
        if not row:
            return {
                "success": False,
                "task_id": task_id,
                "message": "TASK_NOT_FOUND"
            }

        analysis, report = row

        if analysis.status != "success":
            progress = _read_task_progress(task_id)
            response = {
                "success": True,
                "task_id": task_id,
                "status": analysis.status,
                "message": "Analysis is not completed yet"
                if analysis.status != "failed"
                else "Analysis failed",
                "tool_notes": _parse_tool_notes(analysis.tool_notes),
            }
            if progress:
                response["progress"] = progress
            return response

        if report is None:
            return {
                "success": True,
                "task_id": task_id,
                "status": analysis.status,
                "report": None,
                "message": "Analysis completed without a report",
            }

        return {
            "success": True,
            "task_id": task_id,
            "status": analysis.status,
            "report": {
                "aid": str(analysis.aid),
                "rid": str(report.rid),
                "task_id": analysis.task_id,
                "uid": str(analysis.uid),
                "privacy": analysis.privacy,
                "file_name": analysis.file_name,
                "file_size": analysis.file_size,
                "file_hash": analysis.file_hash,
                "file_path": analysis.file_path,
                "file_type": analysis.file_type,
                "tools": analysis.tools,
                "tool_notes": _parse_tool_notes(analysis.tool_notes),
                "md5": analysis.md5,
                "status": analysis.status,
                "deleted_at": analysis.deleted_at.isoformat() if analysis.deleted_at else None,
                "deleted_by": str(analysis.deleted_by) if analysis.deleted_by else None,
                "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
                "report_file_type": report.file_type,
                "virustotal_score": report.virustotal_score,
                "mobsf_score": float(report.mobsf_score) if report.mobsf_score is not None else None,
                "cape_score": float(report.cape_score) if report.cape_score is not None else None,
                "rampart_ai_score": (
                    report.rampart_ai_score if report.rampart_ai_score is not None else None
                ),
                "score": float(report.score) if report.score is not None else None,
                "risk_level": report.risk_level,
                "recommendation": report.recommendation,
                "analysis_summary": report.analysis_summary,
                "risk_indicators": report.risk_indicators,
                "gemini_recommendation": report.gemini_recommendation,
                "malware_signatures": report.malware_signatures,
                "report_created_at": report.created_at.isoformat() if report.created_at else None,
            }
        }
    
async def get_file_by_hash_controller(task_id: str, uid: str, tool: str = "virustotal"):
    try:
        uid = parse_uuid(uid)
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token payload")

    tool = (tool or "virustotal").strip().lower()
    prefix = TOOL_REPORT_PREFIX.get(tool, "virustotal")

    async with SessionLocal() as session:
        user = await session.get(User, uid)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        if user.is_banned:
            raise HTTPException(status_code=403, detail="Account is banned")
        row = await get_analysis_with_report(session, task_id, uid=uid)
        if not row:
            row = await get_public_analysis_with_report(session, task_id)
        if not row and user.role in ADMIN_ROLES:
            row = await get_analysis_with_report_admin(session, task_id)
            if row:
                await write_audit_log(
                    session,
                    actor_uid=user.uid,
                    target_uid=row[0].uid,
                    action="view_private_report_target",
                    detail=f"task_id={task_id} tool={tool}",
                )
                await session.commit()
        if not row:
            return {
                "success": False,
                "task_id": task_id,
                "message": "TASK_NOT_FOUND"
            }

        analysis, report = row

        if analysis.status != "success":
            return {
                "success": True,
                "task_id": task_id,
                "status": analysis.status,
                "message": "Analysis is not completed yet"
            }

        path = (BASE_REPORT_PATH / f"{prefix}-{analysis.md5}.json").resolve()
        try:
            if path.parent == BASE_REPORT_PATH.resolve() and path.is_file():
                async with aiofiles.open(path, "r", encoding="utf-8") as f:
                    content = await f.read()
                    data = json.loads(content)
            else:
                data = {"error": "file not found", "tool": tool}
        except Exception as e:
            data = {"error": str(e), "tool": tool}

        return{
            "success": True,
            "task_id": task_id,
            "status": analysis.status,
            "tool": tool,
            "report":data
        }

async def downloadReport_controller(file_name:str):
    if not FILENAME_REGEX.fullmatch(file_name):
        raise HTTPException(status_code=400, detail="Invalid file name format")

    file_path = (BASE_REPORT_PATH / file_name).resolve()

    if file_path.parent != BASE_REPORT_PATH.resolve():
        raise HTTPException(status_code=403, detail="Access denied")

    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="Report not found")
    return file_path

async def update_privacy_controller(task_id: str, token: str, privacy: bool):
    payload, err = TokenService.verify_token(token, "access")
    if err:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    uid = payload.get("sub")
    if not uid:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    try:
        uid = parse_uuid(uid)
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token payload")

    async with SessionLocal() as session:
        row = await get_analysis_with_report(session, task_id, uid=uid)
        if not row:
            raise HTTPException(status_code=404, detail="TASK_NOT_FOUND")
        analysis, _ = row
        analysis.privacy = bool(privacy)
        await session.commit()
        await session.refresh(analysis)
        invalidate_cached(TASK_STATUS_CACHE_NAMESPACE)
        return {
            "success": True,
            "task_id": str(analysis.task_id),
            "privacy": analysis.privacy,
            "message": "อัปเดตความเป็นส่วนตัวของรายงานสำเร็จ",
        }

async def history_controller(body: AnalysisHistoryParams):
    from services.analy.analy_service import (
        ANALYSIS_HISTORY_CACHE_NAMESPACE,
        ANALYSIS_HISTORY_CACHE_TTL_SECONDS,
    )
    async with SessionLocal() as session:
        try:
            user = await get_current_user(session, body.token)
            ensure_not_banned(user)
        except AuthError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message)

        try:
            suffix = build_suffix(
                uid=str(user.uid),
                page=body.page,
                limit=body.limit,
                s=body.s,
                status=body.status,
                file_type=body.file_type,
                created_at=body.created_at,
                file_name=body.file_name,
                file_size=body.file_size,
                score=body.score,
            )
            return await cached_async(
                ANALYSIS_HISTORY_CACHE_NAMESPACE,
                ANALYSIS_HISTORY_CACHE_TTL_SECONDS,
                lambda: get_analysis_history(session, user.uid, body),
                suffix=suffix,
            )
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=500, detail="Internal server error")
