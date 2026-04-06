from pathlib import Path
import re
import aiofiles
from fastapi import UploadFile, HTTPException
from bgProcessing.tasks import analyze_malware_task
from cores.async_pg_db import SessionLocal
from cores.models_class import User
from schemas.analy import AnalysisHistoryParams 
from services.analy.analy_service import get_analysis_history, get_analysis_with_report, get_file_by_hash, insert_table_analy
from services.token_service import TokenService
import os
from pathlib import Path
from cores.redis import redis_client
from utils.calculate_hash import calculate_hash_from_chunks
from utils.jwt import create_token
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
ALLOWED_PLATFORMS = {"cape", "virustotal", "mobsf"}
FILENAME_REGEX = re.compile(r"^(cape|virustotal|mobsf)-([a-fA-F0-9]{32})$")

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

async def require_upload_token(token: str):
    payload, err = TokenService.verify_token(token, "upload")
    if err:
        raise HTTPException(status_code=401, detail="Invalid upload token")

    uid = payload["sub"]
    session_key = f"upload_session:{uid}"

    stored_token = redis_client.get(session_key)
    if not stored_token or stored_token != token:
        raise HTTPException(status_code=401, detail="Upload token is invalid or already used")

    # redis_client.delete(session_key)

    return int(uid)

async def generateToken_controller(token):
    payload, err = TokenService.verify_token(token, "access")
    if err: 
        return err

    uid = payload["sub"]
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

async def scanFile_controller(
    file: UploadFile,
    uid: int,
    privacy: bool
):
    async with SessionLocal() as session:
        user = await session.get(User, uid)
        if not user:
            raise HTTPException(
                status_code=401,
                detail={
                    "success": False,
                    "code": "USER_NOT_FOUND",
                    "message": "ไม่พบผู้ใช้งานในระบบ"
                }
            )
        if user.status.lower() != "active":
            raise HTTPException(
                status_code=403,
                detail={
                    "success": False,
                    "code": "USER_NOT_ACTIVE",
                    "message": "ผู้ใช้งานไม่อยู๋ในสถานะ active กรุณาติดต่อผู้ดูแลระบบ"
                }
            )
        # ========================= Read & Chunk file =========================
        file_path = None
        try:
            original_filename = file.filename
            chunks = []
            total_size = 0
            while chunk := await file.read(CHUNK_SIZE):
                total_size += len(chunk)
                if total_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="File size exceeds limit"
                    )
                chunks.append(chunk)
            # ========================= Hash calculation =========================
            hashes = calculate_hash_from_chunks(chunks)
            existing_file = await get_file_by_hash(session, hashes['sha256'])
            if existing_file:
                file_path = Path(existing_file["file_path"])
                if not file_path.exists():
                    async with aiofiles.open(file_path, "wb") as f:
                        for chunk in chunks:
                            await f.write(chunk)
                await insert_table_analy(
                    session=session,
                    uid=uid,
                    rid=existing_file.get('rid'),
                    file_name=original_filename,
                    file_hash=existing_file.get('file_hash'),
                    file_path=existing_file.get('file_path'),
                    file_type=existing_file.get('file_type'),
                    file_size=existing_file.get('file_size'),
                    privacy=privacy,
                    md5=existing_file.get('md5'),
                    tools=existing_file.get('tools'),
                    task_id=existing_file.get('task_id'),
                    status=existing_file.get('status')
                )
                return {
                    "success": True,
                    "file_id": hashes,
                    "filename": original_filename,
                    "file_path": existing_file.get('file_path'),
                    "task_id": existing_file.get('task_id'),
                    "message": "File uploaded and task queued successfully"
                }
            else:
                file_ext = os.path.splitext(original_filename)[1].lower()
                file_path = UPLOAD_DIR / f"{hashes['sha256']}{file_ext}"
                async with aiofiles.open(file_path, "wb") as f:
                    for chunk in chunks:
                        await f.write(chunk)
                # ========================= Dispatch Celery task =========================
                await insert_table_analy(
                    session=session,
                    uid=uid,
                    file_name=original_filename,
                    file_hash=hashes['sha256'],
                    file_path=str(file_path),
                    file_type=file_ext.lstrip("."),
                    file_size=total_size,
                    privacy=privacy,
                    md5=hashes['md5']
                )
                task = analyze_malware_task.delay(
                    str(file_path),
                    hashes,
                    int(total_size),
                    analysis_tool='mobsf,cape'
                )
                return {
                    "success": True,
                    "file_id": hashes,
                    "filename": original_filename,
                    "file_path": str(file_path),
                    "task_id": task.id,
                    "message": "File uploaded and task queued successfully"
                }
        except HTTPException:
            raise
        except Exception as e:
            print(f"Upload Error: {e}")
            raise HTTPException(
                status_code=500,
                detail="Internal Server Error"
            )

async def analysisReport_controller(uid: int, task_id: str):
    async with SessionLocal() as session:
        row = await get_analysis_with_report(session, task_id, uid=int(uid))
        
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

        return {
            "success": True,
            "task_id": task_id,
            "status": analysis.status,
            "report": {
                "aid": analysis.aid,
                "rid": report.rid,
                "task_id": analysis.task_id,
                "uid": analysis.uid,
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
                "deleted_by": analysis.deleted_by,
                "created_at": analysis.created_at,
                # report fields
                "rampart_score": float(report.rampart_score) if report.rampart_score else None,
                "package": report.package,
                "type": report.type,
                "score": float(report.score) if report.score else None,
                "risk_level": report.risk_level,
                "recommendation": report.recommendation,
                "analysis_summary": report.analysis_summary,
                "risk_indicators": report.risk_indicators,
            }
        }
    
async def get_file_by_hash_controller(task_id: str,uid: int,tool: str):
    async with SessionLocal() as session:
        row = await get_analysis_with_report(session, task_id, uid=int(uid))
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
        
        path = f"./reports/{tool.value}-{analysis.md5}.json"
        print(f"Looking for report at: {path}")
        try:
            if os.path.exists(path):
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
    match = FILENAME_REGEX.match(file_name)
    if not match:
        raise HTTPException(status_code=400, detail="Invalid file name format")

    platform, md5 = match.groups()

    if platform not in ALLOWED_PLATFORMS:
        raise HTTPException(status_code=400, detail="Invalid platform")
    
    file_path = (BASE_REPORT_PATH / f"{platform}-{md5}.json").resolve()

    if not str(file_path).startswith(str(BASE_REPORT_PATH)):
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
        uid = int(uid)
    except (ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid token payload")
    async with SessionLocal() as session:
        try:
            return await get_analysis_history(session, uid, body)
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=500, detail="Internal server error")

