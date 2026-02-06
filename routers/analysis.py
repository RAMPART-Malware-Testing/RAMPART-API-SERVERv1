from fastapi import APIRouter, File, Request, UploadFile
from controller.analysis_controller import upload_file_controller
from controller.auth_controller import login_confirm_controller
from schemas.auth import LoginConfirmUser, AccessToken

router = APIRouter(
    prefix="/api",
    tags=["analy"]
)

@router.post("/analy/upload")
async def uploadFile(file: UploadFile = File(...)):
    # return {}
    return await upload_file_controller(file)

# @router.post("/analy/report")
# async def login_confirm(data: LoginConfirmUser, request: Request):
#     user_agent = request.headers.get("user-agent", "")
#     ip = request.client.host if request.client else "unknown"
#     return await login_confirm_controller(data, user_agent, ip)
