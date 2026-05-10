import os
import shutil
import hashlib
from pathlib import Path
from tempfile import NamedTemporaryFile
from fastapi import UploadFile, HTTPException, status
from bgProcessing.tasks import analyze_malware_task
from cores.async_pg_db import SessionLocal
from cores.Schema.schema_class import User
from services.analy.analy_service import get_file_by_hash, insert_table_analy
from cores.redis import redis_client

UPLOAD_DIR = Path("temps_files")
REPORTS_DIR = Path("reports")
RESULTS_DIR = Path("results")

for directory in [UPLOAD_DIR, REPORTS_DIR, RESULTS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024 
CHUNK_SIZE = 1024 * 1024 
REDIS_CACHE_TTL = 300 

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

        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        accumulated_size = 0
        original_filename = file.filename
        file_extension = os.path.splitext(original_filename)[1].lower()

        try:
            with NamedTemporaryFile(delete=False, dir=UPLOAD_DIR, prefix="upload_", suffix=".tmp") as temp_file:
                temp_file_path = Path(temp_file.name)

                while chunk := await file.read(CHUNK_SIZE):
                    accumulated_size += len(chunk)
                    
                    if accumulated_size > MAX_FILE_SIZE:
                        os.unlink(temp_file_path)
                        raise HTTPException(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail="File size exceeds the permitted limit."
                        )
                        
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
                    
                    temp_file.write(chunk)

            final_md5 = md5_hash.hexdigest()
            final_sha256 = sha256_hash.hexdigest()
            target_file_path = UPLOAD_DIR / f"{final_sha256}{file_extension}"

            existing_analysis_record = await get_file_by_hash(db_session, final_sha256)

            if existing_analysis_record:
                
                os.unlink(temp_file_path) 
                
                task_id = existing_analysis_record.get('task_id')
                
                # Check for empty task_id and re-trigger analysis if necessary
                if not task_id or task_id.strip() == "":
                    # Ensure the file exists before re-queuing
                    if not target_file_path.exists():
                        raise HTTPException(
                            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="File associated with existing record not found. Cannot re-analyze."
                        )

                    analysis_task = analyze_malware_task.delay(
                        str(target_file_path),
                        str(final_md5),
                        str(final_sha256),
                        int(existing_analysis_record.get('file_size') or accumulated_size)
                    )
                    task_id = analysis_task.id
                    
                    # Optional: Update the status back to analyzing if it was failed
                    status_val = "analyzing"
                else:
                    status_val = existing_analysis_record.get('status')
                    
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
                    task_id=task_id,
                    status=status_val
                )
                
                return {
                    "success": True,
                    "md5": final_md5,
                    "sha256": final_sha256,
                    "filename": original_filename,
                    "task_id": task_id,
                    "message": "File processed successfully. Analysis re-queued or existing result returned."
                }

            
            shutil.move(temp_file_path, target_file_path)

            redis_cache_key = f"analyzing_task:{final_sha256}"
            cached_task_id = None
            
            try:
                cached_task_id = redis_client.get(redis_cache_key)
            except Exception as redis_error:
                print(f"Redis cache retrieval error: {redis_error}")

            if cached_task_id:
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
            if 'temp_file_path' in locals() and os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
            raise
        except Exception as execution_error:
            print(f"Upload and processing error: {execution_error}")
            if 'temp_file_path' in locals() and os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An internal server error occurred while processing the file."
            )