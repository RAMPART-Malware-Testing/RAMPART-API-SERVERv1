from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import os
import aiofiles
import hashlib
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

from bgProcessing.tasks import analyze_malware_task
from celery.result import AsyncResult
from bgProcessing.celery_app import celery_app

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

UPLOAD_DIR = Path("Files/files")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

REPORT_DIR = Path("Files/report")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024
VIRUSTOTAL_MAX_SIZE = 32 * 1024 * 1024

MOBSF_SUPPORTED_EXTENSIONS = ['.apk', '.xapk', '.ipa', '.appx', '.zip']
CAPE_SUPPORTED_EXTENSIONS = ['.exe', '.dll', '.bin', '.msi', '.scr', '.com', '.bat', '.cmd', '.vbs', '.jar']

def calculate_file_hashes(file_path):
    """คำนวณ hash ของไฟล์ (MD5, SHA1, SHA256)"""
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

    return {
        'md5': md5_hash.hexdigest(),
        'sha1': sha1_hash.hexdigest(),
        'sha256': sha256_hash.hexdigest()
    }

def calculate_hash_from_chunks(chunks_data):
    """คำนวณ SHA256 hash จาก chunks ของไฟล์ที่อัปโหลด"""
    sha256_hash = hashlib.sha256()
    for chunk in chunks_data:
        sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def find_existing_file_by_hash(sha256_hash, file_extension):
    """ค้นหาไฟล์ที่มี hash ตรงกันใน upload directory"""
    # ใช้ hash เป็นชื่อไฟล์ - เร็วกว่าการวนลูปหาทุกไฟล์
    expected_file = UPLOAD_DIR / f"{sha256_hash}{file_extension}"
    if expected_file.exists() and expected_file.is_file():
        return expected_file
    return None

def determine_analysis_tool(file_extension):
    """กำหนดเครื่องมือที่จะใช้วิเคราะห์ตาม extension"""
    file_extension = file_extension.lower()

    if file_extension in MOBSF_SUPPORTED_EXTENSIONS:
        return 'mobsf'
    elif file_extension in CAPE_SUPPORTED_EXTENSIONS:
        return 'cape'
    else:
        return 'unsupported'

@app.get('/')
async def root():
    return {"success":True}

@app.get('/api/task/{task_id}')
async def get_task_status(task_id: str):
    task_result = AsyncResult(task_id, app=celery_app)

    if task_result.state == 'PENDING':
        response = {
            "task_id": task_id,
            "status": "pending",
            "message": "Task is waiting to be processed"
        }
    elif task_result.state == 'STARTED':
        response = {
            "task_id": task_id,
            "status": "started",
            "message": "Task is currently being processed"
        }
    elif task_result.state == 'SUCCESS':
        response = {
            "task_id": task_id,
            "status": "success",
            "result": task_result.result,
            "message": "Task completed successfully"
        }
    elif task_result.state == 'FAILURE':
        response = {
            "task_id": task_id,
            "status": "failed",
            "error": str(task_result.info),
            "message": "Task failed"
        }
    else:
        response = {
            "task_id": task_id,
            "status": task_result.state.lower(),
            "message": f"Task state: {task_result.state}"
        }

    return response

@app.post('/api/upload')
async def uploadFile(
    file: UploadFile = File(...),
):
    file_path = None
    file_already_exists = False

    # try:
    file_extension = os.path.splitext(file.filename)[1]

    chunks = []
    total_size = 0

    while chunk := await file.read(CHUNK_SIZE):
        total_size += len(chunk)

        if total_size > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail="File size exceeds 1 GB limit"
            )

        chunks.append(chunk)

    # คำนวณ hash จาก chunks
    sha256_hash = calculate_hash_from_chunks(chunks)

    file_id = sha256_hash
    file_path = UPLOAD_DIR / f"{file_id}{file_extension}"

    # ตรวจสอบว่ามีไฟล์เดิมอยู่แล้วหรือไม่
    if file_path.exists():
        file_already_exists = True
    else:
        async with aiofiles.open(file_path, 'wb') as f:
            for chunk in chunks:
                await f.write(chunk)
        file_already_exists = False

    # คำนวณ hash ของไฟล์ (ทั้ง MD5, SHA1, SHA256)
    file_hashes = calculate_file_hashes(file_path)

    # กำหนดเครื่องมือที่จะใช้วิเคราะห์
    analysis_tool = determine_analysis_tool(file_extension)

    if analysis_tool == 'unsupported':
        if file_path.exists():
            os.remove(file_path)
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {file_extension}. Supported types: {MOBSF_SUPPORTED_EXTENSIONS + CAPE_SUPPORTED_EXTENSIONS}"
        )

    # ตรวจสอบกับ VirusTotal ด้วย hash ก่อน
    # x = VirusTotal().get_report_by_hash(file_hashes.get("md5",""))
    # vt_result = None
    # if total_size <= VIRUSTOTAL_MAX_SIZE:
        # TODO: ตรวจสอบ hash กับ VirusTotal ก่อน
        # from Calling.VirusTotal import VirusTotal
        # vt = VirusTotal()
        # vt_result = vt.check_hash(file_hashes['sha256'])
    
        # ถ้าไม่พบใน VirusTotal ให้อัปโหลดไฟล์
        # if not vt_result:
        #     vt_result = vt.upload_file(str(file_path))
        # pass

    # ส่งไปวิเคราะห์ที่ MobSF หรือ CAPE (คอมเม้นไว้ก่อน)
    # if analysis_tool == 'mobsf':
    #     # TODO: ส่งไปวิเคราะห์ที่ MobSF
    #     # from Calling.MobSF import MobSF
    #     # mobsf = MobSF()
    #     # mobsf_result = mobsf.scan_file(str(file_path))
    #     pass
    # elif analysis_tool == 'cape':
    #     # TODO: ส่งไปวิเคราะห์ที่ CAPE Sandbox
    #     # from Calling.CAPE import CAPE
    #     # cape = CAPE()
    #     # cape_result = cape.submit_file(str(file_path))
    #     pass

    # สร้าง Task Queue สำหรับวิเคราะห์ไฟล์แบบ Background
    tools = []
    if total_size <= VIRUSTOTAL_MAX_SIZE:
        tools.append("virustotal")
    tools.append(analysis_tool)

    # ส่ง task ไป Celery (ทำงานแบบ async ใน background)
    task = analyze_malware_task.delay(str(file_path), tools)

    return {
        "success": True,
        "file_id": file_id,
        "filename": file.filename,
        "file_path": str(file_path),
        "file_size": total_size,
        "file_extension": file_extension,
        "hashes": file_hashes,
        "analysis_tool": analysis_tool,
        "virustotal_eligible": total_size <= VIRUSTOTAL_MAX_SIZE,
        "file_already_exists": file_already_exists,
        "task_id": task.id,  # Task ID สำหรับติดตามสถานะ
        "task_status": "queued",  # สถานะเริ่มต้น
        "message": (f"File already exists, using existing file. " if file_already_exists else f"File uploaded successfully. ") +
                    f"Task queued for analysis using {analysis_tool.upper()}" +
                    (f" and VirusTotal" if total_size <= VIRUSTOTAL_MAX_SIZE else " (VirusTotal: file too large)")
    }

    # except HTTPException:
    #     # ถ้าไฟล์เป็นไฟล์ใหม่ที่เพิ่งสร้าง ให้ลบทิ้ง
    #     print('x')
    #     if file_path and file_path.exists() and not file_already_exists:
    #         os.remove(file_path)
    #     raise
    # except Exception as e:
    #     # ถ้าไฟล์เป็นไฟล์ใหม่ที่เพิ่งสร้าง ให้ลบทิ้ง
    #     if file_path and file_path.exists() and not file_already_exists:
    #         os.remove(file_path)
    #     raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

if __name__=="__main__":
    uvicorn.run("start_server:app", host="0.0.0.0", port=8006, reload=True)
