from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import os
import aiofiles
import hashlib
from pathlib import Path
from dotenv import load_dotenv
import json
from datetime import datetime

load_dotenv()

# Import Tasks
from bgProcessing.tasks import analyze_malware_task
from celery.result import AsyncResult
from bgProcessing.celery_app import celery_app

# Import Utils (สมมติว่ามีไฟล์เหล่านี้)
from utils.calculate_hash import calculate_file_hashes, calculate_hash_from_chunks
from db.redis import redis_client

app = FastAPI(
    title="RAMPART-AI",
    description="RAMPART-AI Models Testing",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path("temps_files")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024  # 1GB
CHUNK_SIZE = 1024 * 1024
VIRUSTOTAL_MAX_SIZE = 32 * 1024 * 1024

MOBSF_SUPPORTED_EXTENSIONS = ['.apk', '.xapk', '.ipa', '.appx']
CAPE_SUPPORTED_EXTENSIONS = ['.exe', '.dll', '.bin', '.msi', '.scr', '.com', '.bat', '.cmd', '.vbs', '.jar',]
VT_SUPPORTED_EXTENSIONS = ['.zip']

# ==========================================
# Helper Functions
# ==========================================

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

def save_file_info_to_redis(sha256_hash, file_path, original_filename, file_hashes, file_size, file_extension):
    try:
        redis_key = f"file:{sha256_hash}"
        upload_time = datetime.now().isoformat()

        redis_client.hset(redis_key, mapping={
            'path': str(file_path),
            'original_filename': original_filename,
            'md5': file_hashes['md5'],
            'sha1': file_hashes['sha1'],
            'sha256': file_hashes['sha256'],
            'file_size': str(file_size),
            'upload_time': upload_time,
            'file_extension': file_extension
        })
        return True
    except Exception as e:
        print(f"Redis error when saving file info: {e}")
        return False

def determine_analysis_tool(file_extension):
    file_extension = file_extension.lower()
    if file_extension in MOBSF_SUPPORTED_EXTENSIONS:
        return 'mobsf'
    elif file_extension in CAPE_SUPPORTED_EXTENSIONS:
        return 'cape'
    elif file_extension in VT_SUPPORTED_EXTENSIONS:
        return 'vt'
    else:
        return 'unsupported'

# ==========================================
# Endpoints
# ==========================================

@app.get('/')
async def root():
    return { "success": True, "message": "RAMPART-AI API is running" }

@app.get('/api/task/{task_id}')
async def get_task_status(task_id: str):
    task_result = AsyncResult(task_id, app=celery_app)
    
    # State handling เหมือนเดิม...
    if task_result.state == 'PENDING':
        response = {"task_id": task_id, "status": "pending", "message": "Task is waiting"}
    elif task_result.state == 'STARTED':
        response = {"task_id": task_id, "status": "started", "message": "Processing"}
    elif task_result.state == 'SUCCESS':
        response = {"task_id": task_id, "status": "success", "result": task_result.result}
    elif task_result.state == 'FAILURE':
        response = {"task_id": task_id, "status": "failed", "error": str(task_result.info)}
    else:
        response = {"task_id": task_id, "status": task_result.state.lower()}

    return response

@app.post('/api/upload')
async def uploadFile(file: UploadFile = File(...)):
    file_path = None
    file_already_exists = False
    
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
        # 3. Check Redis for Deduplication
        existing_file_info = get_file_info_from_redis(sha256_hash)
        print(f"existing_file_info : {existing_file_info}")

        if existing_file_info:
            file_already_exists = True
            file_path = Path(existing_file_info['path'])
            file_hashes = {
                'md5': existing_file_info['md5'],
                'sha1': existing_file_info['sha1'],
                'sha256': existing_file_info['sha256']
            }
            total_size = existing_file_info['file_size']

            # Case: ข้อมูลมีใน Redis แต่ไฟล์จริงหายไป -> สร้างใหม่
            if not file_path.exists():
                file_path = UPLOAD_DIR / original_filename
                async with aiofiles.open(file_path, 'wb') as f:
                    for chunk in chunks:
                        await f.write(chunk)
                
                # Re-calculate hash to be safe
                file_hashes = calculate_file_hashes(file_path)
                save_file_info_to_redis(sha256_hash, file_path, original_filename, file_hashes, total_size, file_extension)
                file_already_exists = False
        
        else:
            # Case: New File
            file_path = UPLOAD_DIR / original_filename
            
            # Handle Duplicate Filenames on Disk
            if file_path.exists():
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename_without_ext = os.path.splitext(original_filename)[0]
                file_path = UPLOAD_DIR / f"{filename_without_ext}_{timestamp}{file_extension}"

            async with aiofiles.open(file_path, 'wb') as f:
                for chunk in chunks:
                    await f.write(chunk)

            file_hashes = calculate_file_hashes(file_path)
            save_file_info_to_redis(sha256_hash, file_path, original_filename, file_hashes, total_size, file_extension)

        # 4. Determine Tool
        analysis_tool = determine_analysis_tool(file_extension)

        if analysis_tool == 'unsupported':
            if file_path.exists() and not file_already_exists:
                os.remove(file_path)
            raise HTTPException(
                status_code=400, 
                detail=f"Unsupported file type: {file_extension}. Supported: {MOBSF_SUPPORTED_EXTENSIONS + CAPE_SUPPORTED_EXTENSIONS}"
            )

        # 5. Dispatch to Celery
        total_size = int(total_size)
        print("*"*100)
        print(str(file_path), file_hashes, total_size, analysis_tool)
        task = analyze_malware_task.delay(str(file_path), file_hashes, total_size, analysis_tool)

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
        # Cleanup: ลบไฟล์ถ้าเกิด Error ระหว่าง process แล้วไฟล์ถูกสร้างขึ้นมาใหม่
        if file_path and file_path.exists() and not file_already_exists:
            try:
                os.remove(file_path)
            except: pass
        
        print(f"Upload Error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")

if __name__=="__main__":
    uvicorn.run("start_server:app", host="0.0.0.0", port=8006, reload=True)