from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from controller.analysis_controller import generateTokenAnaly, get_analysis_report, require_upload_token, upload_file_controller, downloadReport
from deps.auth import require_access_token
from schemas.analy import AnalysisReportParams, GenerateTokenParams
from services.token_service import TokenService

router = APIRouter(
    prefix="/api/analy/v1",
    tags=["analy"]
)

@router.post("/generate-token")
async def generateToken(body: GenerateTokenParams):
    token = body.token
    return await generateTokenAnaly(token)

@router.post("/upload")
async def uploadFile(
    token: str,
    file: UploadFile = File(...),
    privacy: bool = Form(False)
):  
    uid = await require_upload_token(token)
    return await upload_file_controller(file, uid, privacy)

@router.post("/task_id")
async def analyReport(payload: AnalysisReportParams):
    verify, err = TokenService.verify_token(payload.token, "access")
    if err: raise HTTPException(status_code=401, detail="Invalid upload token")
    uid = verify['sub']
    return await get_analysis_report(uid, payload.task_id)

@router.get("/download/report/{file_name}")
async def download_report(file_name: str):
    print(file_name)
    file_path = await downloadReport(file_name)
    return FileResponse(
        path=file_path,
        media_type="application/json",
        filename=file_path.name
    )

