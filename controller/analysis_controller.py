from datetime import datetime
import os
from pathlib import Path
from fastapi import UploadFile, HTTPException
from bgProcessing.tasks import analyze_malware_task
from cores.async_pg_db import SessionLocal
from cores.models_class import User
from services.analy_service import get_file_by_hash, get_table_analy, get_table_uploads, insert_table_analy, insert_table_files, insert_table_uploads, touch_upload_time
from utils.calculate_hash import calculate_file_hashes, calculate_hash_from_chunks
import os
import aiofiles
from pathlib import Path
from cores.redis import redis_client
from sqlalchemy import select

UPLOAD_DIR = Path("temps_files")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

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

# def save_file_info_to_redis(sha256_hash, file_path, original_filename, file_hashes, file_size, file_extension):
#     try:
#         redis_key = f"file:{sha256_hash}"
#         upload_time = datetime.now().isoformat()

#         redis_client.hset(redis_key, mapping={
#             'path': str(file_path),
#             'original_filename': original_filename,
#             'md5': file_hashes['md5'],
#             'sha1': file_hashes['sha1'],
#             'sha256': file_hashes['sha256'],
#             'file_size': str(file_size),
#             'upload_time': upload_time,
#             'file_extension': file_extension
#         })
#         return True
#     except Exception as e:
#         print(f"Redis error when saving file info: {e}")
#         return False

def determine_analysis_tool(file_extension):
    file_extension = file_extension.lower()
    if file_extension in MOBSF_SUPPORTED_EXTENSIONS:
        return 'mobsf'
    elif file_extension in CAPE_SUPPORTED_EXTENSIONS:
        return 'cape'
    else:
        return 'mobsf,cape'


async def upload_file_controller(file: UploadFile, username:str, privacy:bool):
    # ตรวจสอบ status ผู้ใช้
    async with SessionLocal() as session:
        result = await session.execute(
            select(User).where(User.username == username)
        )
        user = result.scalar_one_or_none()
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
                "code": f"USER IS : {user.status}, USER_NOT_ACTIVE",
                "message": "User account is not active"
            }
        )
    # เริ่มตรวจสอบค่า hash ของไฟล์และกระบวนการตรวจสอบอื่นๆ
    file_path = None
    try:
        original_filename = file.filename
        file_extension = os.path.splitext(original_filename)[1]

        # 1. Read & Chunk Logic
        chunks = []
        total_size = 0
        while chunk := await file.read(CHUNK_SIZE):
            total_size += len(chunk)
            if total_size > MAX_FILE_SIZE:
                raise HTTPException(status_code=413, detail="File size exceeds 1 GB limit")
            chunks.append(chunk)

        # 2. Hash Calculation
        sha256_hash = calculate_hash_from_chunks(chunks)

        # Check database
        async with SessionLocal() as session:
            existing_file = await get_file_by_hash(session, sha256_hash)
            if existing_file:
                file_path = Path(existing_file.file_path)
                if not file_path.exists():
                    async with aiofiles.open(file_path, 'wb') as f:
                        for chunk in chunks:
                            await f.write(chunk)
            else:
                file_ext = os.path.splitext(file.filename)[1]
                file_path = UPLOAD_DIR / f"{sha256_hash}{file_ext}"
                
                async with aiofiles.open(file_path, "wb") as f:
                    for chunk in chunks:
                        await f.write(chunk)

                # Save to database
                db_file = await insert_table_files(
                    session,
                    file_hash=sha256_hash,
                    file_path=str(file_path),
                    file_type=file.content_type,
                    file_size=total_size
                )

                existing_file = db_file
                print(f"uploaded ==> file ID : {db_file.fid}, {sha256_hash}{file_ext}")
            # ตรวจสอบการไฟล์ซ้ำรายบุคคล ถ้าส่งไฟล์เดิมมาซ้ำจะดึง task อันแรกไม่ต้อง วิเคราะห์ใหม่และไม่ต้องบันทึกลงฐานข้อมูลเพิ่ม (not insert table uploads)
            existing_upload = await get_table_uploads(
                session,
                uid=user.uid,
                fid=existing_file.fid,
                file_name=file.filename
            )
            if existing_upload:
                # อัปเดตเวลาให้เป็นปัจจุบัน
                await touch_upload_time(session, existing_upload)
                analysis = await get_table_analy(session, existing_file.fid)
                if analysis:
                    return {
                        "success": True,
                        "message": "File already uploaded",
                        "file_id": sha256_hash,
                        "filename": file.filename,
                        "task_id": analysis.task_id,
                        "status": analysis.status
                    }
            else:
                # ในกรณีที่ไม่ใช่คนเดียวกันแต่ไฟล์ซ้ำจะบันทึกลงฐานข้อมูล (insert table uploads)
                upload_row = await insert_table_uploads(
                    session=session,
                    uid=user.uid,
                    fid=existing_file.fid,
                    file_name=file.filename,
                    privacy=privacy
                )
            # ตรวจสอบการวิเคราะห์ ถ้าไฟล์นี้วิเคราะห์ซ้ำกับคนอื่นที่วิเคราะห์ก่อนแล้วในระบบ จะดึงเอา task เดียวกันออกไปเลย แล้วค่อยเอา task ไปดึง report (check table analy)
            existing_analysis = await get_table_analy(session, existing_file.fid)
            if existing_analysis:
                return {
                    "success": True,
                    "file_id": sha256_hash,
                    "filename": file.filename,
                    "file_path": str(file_path),
                    "task_id": existing_analysis.task_id,
                    "message": "Analysis already pending"
                }


            # 4. Determine Tool
            analysis_tool = determine_analysis_tool(file_extension)
            file_hashes = calculate_file_hashes(file_path)
            # 5. Dispatch to Celery
            total_size = int(total_size)
            analysis = await insert_table_analy(
                session=session,
                fid=existing_file.fid,
                platform=[analysis_tool]
            )
            task = analyze_malware_task.delay(analysis.aid, str(file_path), file_hashes, total_size, analysis_tool)


        return {
            "success": True,
            "file_id": sha256_hash,
            "filename": original_filename,
            "file_path": str(file_path),
            "tool": analysis_tool,
            "task_id": task.id,
            "message": "File uploaded and task queued successfully."
        }
    except HTTPException:
        raise # ปล่อยผ่านให้ FastAPI จัดการ response
    except Exception as e:
        print(f"Upload Error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal Server Error: {str(e)}"
        )

