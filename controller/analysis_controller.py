# from datetime import datetime
from pathlib import Path
import re
# import re
import aiofiles
from fastapi import Header, UploadFile, HTTPException
# from bgProcessing.tasks import analyze_malware_task
from bgProcessing.tasks import analyze_malware_task
from cores.async_pg_db import SessionLocal
from cores.models_class import User
from services.analy.analy_service import get_analy_by_task_id, get_file_by_hash, get_report, insert_table_analy
from services.token_service import TokenService
import os
from pathlib import Path
from cores.redis import redis_client
from utils.calculate_hash import calculate_hash_from_chunks
from utils.jwt import create_token
# from utils.response import error, success

UPLOAD_DIR = Path("temps_files")
REPORTS_DIR = Path("reports")

for directory in [UPLOAD_DIR, REPORTS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024  # 1GB
CHUNK_SIZE = 1024 * 1024
VIRUSTOTAL_MAX_SIZE = 32 * 1024 * 1024

MOBSF_SUPPORTED_EXTENSIONS = ['.apk', '.xapk', '.ipa', '.appx']
CAPE_SUPPORTED_EXTENSIONS = ['.exe', '.dll', '.bin', '.msi', '.scr', '.com', '.bat', '.cmd', '.vbs', '.jar',]


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

def determine_analysis_tool(file_extension):
    file_extension = file_extension.lower()
    if file_extension in MOBSF_SUPPORTED_EXTENSIONS:
        return 'mobsf'
    elif file_extension in CAPE_SUPPORTED_EXTENSIONS:
        return 'cape'
    else:
        return 'mobsf,cape'
    
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

async def generateTokenAnaly(token):
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
            "message": "Upload token already exists.",
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
        "message": "Upload token created successfully.",
        "data": {
            "upload_token": upload_token,
            "expires_in": UPLOAD_TOKEN_TTL
        }
    }

async def upload_file_controller(
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
                    "message": "User not found"
                }
            )

        if user.status != "ACTIVE":
            raise HTTPException(
                status_code=403,
                detail={
                    "success": False,
                    "code": "USER_NOT_ACTIVE",
                    "message": "User account is not active"
                }
            )

        # ========================= Read & Chunk file =========================
        file_path = None
        try:
            original_filename = file.filename
            file_extension = os.path.splitext(original_filename)[1]

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
                
                if existing_file.get('rid'):
                    analysis = await insert_table_analy(
                        session=session,
                        uid=uid,
                        rid=existing_file['rid'],
                        file_name=original_filename,
                        file_hash=existing_file['file_hash'],
                        file_path=existing_file['file_path'],
                        file_type=existing_file['file_type'],
                        file_size=existing_file['file_size'],
                        privacy=privacy,
                        md5=existing_file['md5'],
                        tools=existing_file['tools'],
                        task_id=existing_file['task_id'],
                        status=existing_file['status']
                    )
                    return {
                        "success": True,
                        "file_id": hashes,
                        "filename": original_filename,
                        "file_path": existing_file['file_path'],
                        "tool": existing_file['tools'],
                        "task_id": existing_file['task_id'],
                        "message": "File uploaded and task queued successfully"
                    }
                else:
                    analysis = await insert_table_analy(
                        session=session,
                        uid=uid,
                        file_name=original_filename,
                        file_hash=existing_file['file_hash'],
                        file_path=existing_file['file_path'],
                        file_type=existing_file['file_type'],
                        file_size=existing_file['file_size'],
                        privacy=privacy,
                        md5=existing_file['md5'],
                        tools=existing_file['tools'],
                        task_id=existing_file['task_id'],
                        status=existing_file['status']
                    )
                    return {
                        "success": True,
                        "file_id": hashes,
                        "filename": original_filename,
                        "file_path": existing_file['file_path'],
                        "tool": existing_file['tools'],
                        "task_id": existing_file['task_id'],
                        "message": "File uploaded and task queued successfully"
                    }

            else:
                file_ext = os.path.splitext(original_filename)[1]
                file_path = UPLOAD_DIR / f"{hashes['sha256']}{file_ext}"
                async with aiofiles.open(file_path, "wb") as f:
                    for chunk in chunks:
                        await f.write(chunk)
                # ========================= Dispatch Celery task =========================
                analysis_tool = determine_analysis_tool(file_extension)
                analysis = await insert_table_analy(
                    session=session,
                    uid=uid,
                    file_name=original_filename,
                    file_hash=hashes['sha256'],
                    file_path=str(file_path),
                    file_type=file.content_type,
                    file_size=total_size,
                    privacy=privacy,
                    md5=hashes['md5']
                )

                task = analyze_malware_task.delay(
                    str(file_path),
                    hashes,
                    int(total_size),
                    analysis_tool
                )

                return {
                    "success": True,
                    "file_id": hashes,
                    "filename": original_filename,
                    "file_path": str(file_path),
                    "tool": analysis_tool,
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

async def get_analysis_report(uid: int, task_id: str):
    async with SessionLocal() as session:
        analysis = await get_analy_by_task_id(session, task_id, uid=int(uid))
        if not analysis:
            return {
                "success": False,
                "task_id": task_id,
                "message": "TASK_NOT_FOUND"
            }

        if analysis.status != "success":
            return {
                "success": True,
                "task_id": task_id,
                "status": analysis.status,
                "message": "Analysis is not completed yet"
            }

        report = await get_report(session, analysis.rid)
        return {
            "success": True,
            "task_id": task_id,
            "status": analysis.status,
            "report": {
                "tools" : analysis.tools,
                "md5" : analysis.md5,
                "rid": report.rid,
                "rampart_score": float(report.rampart_score) if report.rampart_score else None,
                "package": report.package,
                "type": report.type,
                "score": float(report.score) if report.score else None,
                "risk_level": report.risk_level,
                "recommendation": report.recommendation,
                "analysis_summary": report.analysis_summary,
                "risk_indicators": report.risk_indicators,
                "created_at": report.created_at,
            }
        }

BASE_REPORT_PATH = Path("reports").resolve()

ALLOWED_PLATFORMS = {"cape", "virustotal", "mobsf"}

FILENAME_REGEX = re.compile(r"^(cape|virustotal|mobsf)-([a-fA-F0-9]{32})$")

async def downloadReport(file_name:str):
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
    # from fastapi.responses import StreamingResponse

    # def iterfile(path, chunk_size: int = 1024 * 1024):  # 1MB chunk
    #     with open(path, "rb") as f:
    #         while True:
    #             chunk = f.read(chunk_size)
    #             if not chunk:
    #                 break
    #             yield chunk

    # return StreamingResponse(
    #     iterfile(file_path),
    #     media_type="application/json",
    #     headers={
    #         "Content-Disposition": f"attachment; filename={platform}-{md5}.json"
    #     }
    # )
    return file_path

