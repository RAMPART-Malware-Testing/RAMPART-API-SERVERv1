# import sys
# import os

# def force_utf8():
#     os.environ.setdefault("PYTHONIOENCODING", "utf-8")

#     try:
#         sys.stdout.reconfigure(encoding="utf-8")
#         sys.stderr.reconfigure(encoding="utf-8")
#     except Exception:
#         pass  # บาง environment reconfigure ไม่ได้

# force_utf8()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from utils.startup.create_root_user import create_root_user
from celery.result import AsyncResult
from bgProcessing.celery_app import celery_app
from dotenv import load_dotenv
import uvicorn
load_dotenv()

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

@app.on_event("startup")
async def startup_event():
    await create_root_user()
# ==========================================
# Endpoints
# ==========================================
from routers.auth import router as auth_router
from routers.analysis import router as analy_router

app.include_router(auth_router)
app.include_router(analy_router)

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

# @app.post('/api/upload')
# async def uploadFile(file: UploadFile = File(...)):
#     file_path = None
#     file_already_exists = False
    
#     try:
#         original_filename = file.filename
#         file_extension = os.path.splitext(original_filename)[1]

#         # 1. Read & Chunk Logic
#         chunks = []
#         total_size = 0
#         while chunk := await file.read(CHUNK_SIZE):
#             total_size += len(chunk)
#             if total_size > MAX_FILE_SIZE:
#                 raise HTTPException(status_code=413, detail="File size exceeds 1 GB limit")
#             chunks.append(chunk)

#         # 2. Hash Calculation
#         sha256_hash = calculate_hash_from_chunks(chunks)
#         # 3. Check Redis for Deduplication
#         existing_file_info = get_file_info_from_redis(sha256_hash)
#         print(f"existing_file_info : {existing_file_info}")

#         if existing_file_info:
#             file_already_exists = True
#             file_path = Path(existing_file_info['path'])
#             file_hashes = {
#                 'md5': existing_file_info['md5'],
#                 'sha1': existing_file_info['sha1'],
#                 'sha256': existing_file_info['sha256']
#             }
#             total_size = existing_file_info['file_size']

#             # Case: ข้อมูลมีใน Redis แต่ไฟล์จริงหายไป -> สร้างใหม่
#             if not file_path.exists():
#                 file_path = UPLOAD_DIR / original_filename
#                 async with aiofiles.open(file_path, 'wb') as f:
#                     for chunk in chunks:
#                         await f.write(chunk)
                
#                 # Re-calculate hash to be safe
#                 file_hashes = calculate_file_hashes(file_path)
#                 save_file_info_to_redis(sha256_hash, file_path, original_filename, file_hashes, total_size, file_extension)
#                 file_already_exists = False
        
#         else:
#             # Case: New File
#             file_path = UPLOAD_DIR / original_filename
            
#             # Handle Duplicate Filenames on Disk
#             if file_path.exists():
#                 timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
#                 filename_without_ext = os.path.splitext(original_filename)[0]
#                 file_path = UPLOAD_DIR / f"{filename_without_ext}_{timestamp}{file_extension}"

#             async with aiofiles.open(file_path, 'wb') as f:
#                 for chunk in chunks:
#                     await f.write(chunk)

#             file_hashes = calculate_file_hashes(file_path)
#             save_file_info_to_redis(sha256_hash, file_path, original_filename, file_hashes, total_size, file_extension)

#         # 4. Determine Tool
#         analysis_tool = determine_analysis_tool(file_extension)

#         if analysis_tool == 'unsupported':
#             if file_path.exists() and not file_already_exists:
#                 os.remove(file_path)
#             raise HTTPException(
#                 status_code=400, 
#                 detail=f"Unsupported file type: {file_extension}. Supported: {MOBSF_SUPPORTED_EXTENSIONS + CAPE_SUPPORTED_EXTENSIONS}"
#             )

#         # 5. Dispatch to Celery
#         total_size = int(total_size)
#         print("*"*100)
#         print(str(file_path), file_hashes, total_size, analysis_tool)
#         task = analyze_malware_task.delay(str(file_path), file_hashes, total_size, analysis_tool)

#         return {
#             "success": True,
#             "file_id": sha256_hash,
#             "filename": original_filename,
#             "file_path": str(file_path),
#             "tool": analysis_tool,
#             "task_id": task.id,
#             "message": "File uploaded and task queued successfully."
#         }
#     except HTTPException:
#         raise # ปล่อยผ่านให้ FastAPI จัดการ response
#     except Exception as e:
#         # Cleanup: ลบไฟล์ถ้าเกิด Error ระหว่าง process แล้วไฟล์ถูกสร้างขึ้นมาใหม่
#         if file_path and file_path.exists() and not file_already_exists:
#             try:
#                 os.remove(file_path)
#             except: pass
        
#         print(f"Upload Error: {e}")
#         raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")


if __name__=="__main__":
    uvicorn.run("start_server:app", host="0.0.0.0", port=8006, reload=True)