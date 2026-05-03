import os
import shutil
import hashlib
from pathlib import Path
from tempfile import NamedTemporaryFile
from fastapi import UploadFile, HTTPException, status
from bgProcessing.tasks import analyze_malware_task
from cores.async_pg_db import SessionLocal
from cores.models_class import User
from services.analy.analy_service import get_file_by_hash, insert_table_analy
from cores.redis import redis_client

UPLOAD_DIR = Path("temps_files")
REPORTS_DIR = Path("reports")
RESULTS_DIR = Path("results")

for directory in [UPLOAD_DIR, REPORTS_DIR, RESULTS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024 # 1GB
CHUNK_SIZE = 1024 * 1024 # 1MB
REDIS_CACHE_TTL = 300 # 5 นาที

async def scan_file_controller(
    file: UploadFile,
    user_id: int,
    is_private: bool
):
    async with SessionLocal() as db_session:
        user_record = await db_session.get(User, user_id)
        
        if not user_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"success": False, "code": "USER_NOT_FOUND", "message": "User not found."}
            )

        if user_record.status.lower() != "active":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"success": False, "code": "USER_NOT_ACTIVE", "message": "User is not active."}
            )

        # 1. สร้างตัวแปรสำหรับ Hash
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        accumulated_size = 0
        original_filename = file.filename
        file_extension = os.path.splitext(original_filename)[1].lower()

        # 2. สร้างไฟล์ชั่วคราว (Temp File) แบบปลอดภัย ป้องกันไฟล์ซ้ำซ้อนตอนอัปโหลด
        # ไฟล์นี้จะถูกลบอัตโนมัติถ้าเกิด Error ก่อนทำสำเร็จ
        try:
            with NamedTemporaryFile(delete=False, dir=UPLOAD_DIR, prefix="upload_", suffix=".tmp") as temp_file:
                temp_file_path = Path(temp_file.name)

                # 3. สตรีมมิ่ง: อ่าน -> คำนวณ Hash -> เขียนลงไฟล์ (ไม่เก็บลง Memory List)
                while chunk := await file.read(CHUNK_SIZE):
                    accumulated_size += len(chunk)
                    
                    if accumulated_size > MAX_FILE_SIZE:
                        # ลบไฟล์ทิ้งทันทีถ้าขนาดเกินกำหนด
                        os.unlink(temp_file_path)
                        raise HTTPException(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail="File size exceeds the permitted limit."
                        )
                        
                    # คำนวณ Hash เฉพาะก้อน (Chunk) ที่อ่านมา
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
                    
                    # เขียนก้อนข้อมูลลงไฟล์ดิสก์
                    temp_file.write(chunk)

            # ได้ค่า Hash สุดท้ายของไฟล์
            final_md5 = md5_hash.hexdigest()
            final_sha256 = sha256_hash.hexdigest()

            # 4. ตรวจสอบข้อมูลใน Database ก่อน
            existing_analysis_record = await get_file_by_hash(db_session, final_sha256)

            if existing_analysis_record:
                # กรณีที่ 1: พบในฐานข้อมูล (วิเคราะห์เสร็จแล้ว)
                
                # ลบไฟล์ Temp ทิ้งทันที เพราะไม่จำเป็นต้องเก็บไฟล์ซ้ำ
                os.unlink(temp_file_path) 
                
                # บันทึกประวัติการเรียกดูของผู้ใช้
                await insert_table_analy(
                    session=db_session,
                    uid=user_id,
                    rid=existing_analysis_record.get('rid'),
                    file_name=original_filename,
                    file_hash=final_sha256,
                    file_path=existing_analysis_record.get('file_path'),
                    file_type=existing_analysis_record.get('file_type'),
                    file_size=existing_analysis_record.get('file_size'),
                    privacy=is_private,
                    md5=final_md5,
                    tools=existing_analysis_record.get('tools'),
                    task_id=existing_analysis_record.get('task_id'),
                    status=existing_analysis_record.get('status')
                )
                
                return {
                    "success": True,
                    "md5": final_md5,
                    "sha256": final_sha256,
                    "filename": original_filename,
                    "task_id": existing_analysis_record.get('task_id'),
                    "message": "File processed successfully using existing analysis."
                }

            # 5. กรณีไฟล์ใหม่ (ยังไม่มีใน Database): ตรวจสอบว่ากำลังวิเคราะห์อยู่หรือไม่ (Redis)
            target_file_path = UPLOAD_DIR / f"{final_sha256}{file_extension}"
            
            # ย้ายไฟล์ Temp ไปเป็นไฟล์จริง (ถ้าเคยมีไฟล์ค้างไว้จะถูกเขียนทับอย่างปลอดภัย)
            shutil.move(temp_file_path, target_file_path)

            redis_cache_key = f"analyzing_task:{final_sha256}"
            cached_task_id = None
            
            try:
                cached_task_id = redis_client.get(redis_cache_key)
            except Exception as redis_error:
                print(f"Redis cache retrieval error: {redis_error}")

            if cached_task_id:
                # กรณีที่ 2: กำลังวิเคราะห์อยู่โดยผู้ใช้อื่น
                await insert_table_analy(
                    session=db_session,
                    uid=user_id,
                    file_name=original_filename,
                    file_hash=final_sha256,
                    file_path=str(target_file_path),
                    file_type=file_extension.lstrip("."),
                    file_size=accumulated_size,
                    privacy=is_private,
                    md5=final_md5,
                    task_id=cached_task_id,
                    status="analyzing"
                )
                
                return {
                    "success": True,
                    "md5": final_md5,
                    "sha256": final_sha256,
                    "filename": original_filename,
                    "task_id": cached_task_id,
                    "message": "File is already being analyzed. Attached to existing queue."
                }

            # 6. กรณีที่ 3: ไฟล์ใหม่เอี่ยมจริงๆ ต้องส่งเข้าคิววิเคราะห์
            await insert_table_analy(
                session=db_session,
                uid=user_id,
                file_name=original_filename,
                file_hash=final_sha256,
                file_path=str(target_file_path),
                file_type=file_extension.lstrip("."),
                file_size=accumulated_size,
                privacy=is_private,
                md5=final_md5,
                status="analyzing"
            )
            
            analysis_task = analyze_malware_task.delay(
                str(target_file_path),
                str(final_md5),
                str(final_sha256),
                int(accumulated_size)
            )

            try:
                # บันทึกสถานะลง Redis ล็อคไว้ 5 นาที
                redis_client.setex(redis_cache_key, REDIS_CACHE_TTL, analysis_task.id)
            except Exception as redis_error:
                print(f"Redis cache setting error: {redis_error}")

            return {
                "success": True,
                "md5": final_md5,
                "sha256": final_sha256,
                "filename": original_filename,
                "task_id": analysis_task.id,
                "message": "File uploaded and new analysis task queued."
            }

        except HTTPException:
            # ถ้าเป็น HTTP Error เช่น ไฟล์ใหญ่เกิน ให้ส่งต่อเลย และมั่นใจว่า Temp ไฟล์โดนลบในบล็อกแล้ว
            if 'temp_file_path' in locals() and os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
            raise
        except Exception as execution_error:
            # จัดการ Error อื่นๆ ที่ไม่ได้คาดคิด และลบไฟล์ Temp ทิ้งป้องกันขยะ
            print(f"Upload and processing error: {execution_error}")
            if 'temp_file_path' in locals() and os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An internal server error occurred while processing the file."
            )