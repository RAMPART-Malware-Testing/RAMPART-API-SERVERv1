from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from controller.analysis_controller import analysisReport_controller, downloadReport_controller, generateToken_controller,get_file_by_hash_controller, history_controller, require_upload_token, update_privacy_controller
from schemas.analy import AnalysisHistoryParams, AnalysisReportParams, CheckHashParams, GenerateTokenParams,AnalysisReportParamsTarget, UpdatePrivacyParams
from services.token_service import TokenService
from controller.Analysis.ScanFile_controller import scan_file_controller
from controller.Analysis.CheckHash_controller import check_hash_controller

router = APIRouter(
    prefix="/api/analy/v1",
    tags=["analy"]
)

@router.post("/generate-token")
async def generateToken(body: GenerateTokenParams):
    token = body.token
    return await generateToken_controller(token)

@router.post("/upload")
async def uploadFile(
    token: str,
    file: UploadFile = File(...),
    privacy: bool = Form(True)
):
    uid = await require_upload_token(token)
    return await scan_file_controller(file, uid, privacy)

@router.post("/check-hash")
async def checkHash(body: CheckHashParams):
    """Hash-only dedup pre-check: lets the client hash a file locally and
    ask "has this content already been analyzed?" before uploading any
    bytes. Uses an access token (not an upload token) since no file is
    actually being sent here.
    """
    payload, err = TokenService.verify_token(body.token, "access")
    if err: raise HTTPException(status_code=401, detail="Invalid access token")
    uid = payload['sub']
    return await check_hash_controller(uid, body.sha256, body.file_name, body.file_size, body.privacy)

@router.post("/task_id")
async def analyReport(body: AnalysisReportParams):
    payload, err = TokenService.verify_token(body.token, "access")
    if err: raise HTTPException(status_code=401, detail="Invalid upload token")
    uid = payload['sub']
    return await analysisReport_controller(uid, body.task_id)

@router.post("/report_target")
async def getAnalysisReport(body: AnalysisReportParamsTarget):
    payload, err = TokenService.verify_token(body.token, "access")
    if err: raise HTTPException(status_code=401, detail="Invalid upload token")
    uid = payload['sub']
    return await get_file_by_hash_controller(body.task_id, uid, body.tool)


@router.get("/download/report/{file_name}")
async def download_report(file_name: str):
    print(file_name)
    file_path = await downloadReport_controller(file_name)
    return FileResponse(
        path=file_path,
        media_type="application/json",
        filename=file_path.name
    )

@router.post("/history")
async def getHistoryAnalysis(body: AnalysisHistoryParams):
    return await history_controller(body);

@router.patch("/{task_id}/privacy")
async def updatePrivacy(task_id: str, body: UpdatePrivacyParams):
    return await update_privacy_controller(task_id, body.token, body.privacy)

