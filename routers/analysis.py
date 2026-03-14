from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from controller.analysis_controller import analysisReport_controller, downloadReport_controller, generateToken_controller, history_controller, require_upload_token, scanFile_controller, test_controller
from schemas.analy import AnalysisHistoryParams, AnalysisReportParams, GenerateTokenParams
from services.token_service import TokenService

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
    privacy: bool = Form(False)
):  
    uid = await require_upload_token(token)
    return await scanFile_controller(file, uid, privacy)

@router.post("/task_id")
async def analyReport(body: AnalysisReportParams):
    payload, err = TokenService.verify_token(body.token, "access")
    if err: raise HTTPException(status_code=401, detail="Invalid upload token")
    uid = payload['sub']
    return await analysisReport_controller(uid, body.task_id)

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


@router.get("/test-x")
async def testx():
    return await test_controller()
