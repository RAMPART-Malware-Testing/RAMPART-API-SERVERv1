from pathlib import Path
import re
import aiofiles
from fastapi import UploadFile, HTTPException
from fastapi.concurrency import run_in_threadpool
from bgProcessing.tasks import analyze_malware_task
from cores.async_pg_db import SessionLocal
from cores.Schema.schema_class import User
from schemas.analy import AnalysisHistoryParams 
from services.analy.analy_service import get_analysis_history, get_analysis_with_report, get_file_by_hash, insert_table_analy
from services.token_service import TokenService
import os
from pathlib import Path
from cores.redis import redis_client
from utils.calculate_hash import calculate_hash_from_chunks
from utils.jwt import create_token
from utils.uuid import parse_uuid
import json

UPLOAD_DIR = Path("temps_files")
REPORTS_DIR = Path("reports")
RESULTS_DIR = Path("results")

for directory in [UPLOAD_DIR, REPORTS_DIR, RESULTS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024  # 1GB
CHUNK_SIZE = 1024 * 1024
VIRUSTOTAL_MAX_SIZE = 32 * 1024 * 1024

BASE_REPORT_PATH = Path("reports").resolve()
FILENAME_REGEX = re.compile(r"^virustotal-([a-fA-F0-9]{32})\.json$")

def decode_redis_data(data):
    if not data:
        return None
    return {k.decode('utf-8'): v.decode('utf-8') for k, v in data.items()}

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
    payload, err = TokenService.verify_token(token, "access")
    if err: 
        return err

    try:
        uid = str(parse_uuid(payload.get("sub")))
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid access token subject")
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

async def analysisReport_controller(uid: str, task_id: str):
    try:
        uid = parse_uuid(uid)
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token payload")
    async with SessionLocal() as session:
        row = await get_analysis_with_report(session, task_id, uid=uid)
        
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
                "md5": analysis.md5,
                "status": analysis.status,
                "deleted_at": analysis.deleted_at,
                "deleted_by": str(analysis.deleted_by) if analysis.deleted_by else None,
                "created_at": analysis.created_at,
                "report_file_type": report.file_type,
                "virustotal_score": report.virustotal_score,
                "mobsf_score": report.mobsf_score,
                "cape_score": report.cape_score,
                "malware_signatures": report.malware_signatures,
                "report_created_at": report.created_at,
            }
        }
    
async def get_file_by_hash_controller(task_id: str, uid: str):
    try:
        uid = parse_uuid(uid)
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token payload")
    async with SessionLocal() as session:
        row = await get_analysis_with_report(session, task_id, uid=uid)
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
        
        path = (BASE_REPORT_PATH / f"virustotal-{analysis.md5}.json").resolve()
        try:
            if path.parent == BASE_REPORT_PATH.resolve() and path.is_file():
                async with aiofiles.open(path, "r") as f:
                    content = await f.read()
                    data = json.loads(content)
            else:
                data = {"error": "file not found"}
        except Exception as e:
            data = {"error": str(e)}


        return{
            "success": True,
            "task_id": task_id,
            "status": analysis.status,
            "report":data
        }

        return

async def downloadReport_controller(file_name:str):
    if not FILENAME_REGEX.fullmatch(file_name):
        raise HTTPException(status_code=400, detail="Invalid file name format")

    file_path = (BASE_REPORT_PATH / file_name).resolve()

    if file_path.parent != BASE_REPORT_PATH.resolve():
        raise HTTPException(status_code=403, detail="Access denied")

    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="Report not found")
    return file_path

async def history_controller(body: AnalysisHistoryParams):
    payload, err = TokenService.verify_token(body.token, "access")
    if err:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    uid = payload.get("sub")
    if not uid:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    try:
        uid = parse_uuid(uid)
    except (ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid token payload")
    async with SessionLocal() as session:
        try:
            return await get_analysis_history(session, uid, body)
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=500, detail="Internal server error")
