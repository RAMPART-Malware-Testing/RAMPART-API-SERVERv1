from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from controller.analysis_controller import generateTokenAnaly, require_upload_token, upload_file_controller
from deps.auth import require_access_token
from schemas.analy import AnalysisReportRequest, GenerateTokenParams

router = APIRouter(
    prefix="/api/analy/v1",
    tags=["analy"]
)

@router.post("/generate-token")
async def generateToken(body:GenerateTokenParams):
    return await generateTokenAnaly(body)

@router.post("/upload")
async def uploadFile(
    token: str,
    file: UploadFile = File(...),
    privacy: bool = Form(False)
):  
    uid = await require_upload_token(token)
    return await upload_file_controller(file, uid, privacy)

@router.post("/report")
async def analyReport(
    payload: AnalysisReportRequest,
    uid: str = Depends(require_access_token),
):
    return await get_analysis_report(uid, payload.task_id)

# @router.get("/report/{file_name}")
# async def download_report(file_name: str):

#     file_path = get_analy_report(file_name)

#     return FileResponse(
#         path=file_path,
#         media_type="application/json",
#         filename=file_path.name
#     )

