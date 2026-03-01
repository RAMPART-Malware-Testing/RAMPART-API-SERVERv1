from pathlib import Path
import re
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from controller.analysis_controller import get_analy_report, get_analysis_report, upload_file_controller
from deps.auth import require_access_token
from schemas.analy import AnalysisReportRequest

router = APIRouter(
    prefix="/api/analy/v1",
    tags=["analy"]
)

@router.post("/upload")
async def uploadFile(
    file: UploadFile = File(...), 
    uid: str = Depends(require_access_token), 
    privacy:bool = Form(False)
):
    return await upload_file_controller(file, uid, privacy)

@router.post("/report")
async def analyReport(
    payload: AnalysisReportRequest,
    uid: str = Depends(require_access_token),
):
    return await get_analysis_report(uid, payload.task_id)

@router.get("/report/{file_name}")
async def download_report(file_name: str):

    file_path = get_analy_report(file_name)

    return FileResponse(
        path=file_path,
        media_type="application/json",
        filename=file_path.name
    )

