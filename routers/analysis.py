from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from controller.analysis_controller import upload_file_controller
from controller.auth_controller import login_confirm_controller
from deps.auth import require_access_token
from schemas.auth import LoginConfirmUser, AccessToken

router = APIRouter(
    prefix="/api",
    tags=["analy"]
)

@router.post("/analy/upload")
async def uploadFile(file: UploadFile = File(...), username: str = Depends(require_access_token), privacy:bool = Form(False)):
    return await upload_file_controller(file, username, privacy)

# @router.post("/analy/report")
# async def login_confirm(data: LoginConfirmUser, request: Request):
#     user_agent = request.headers.get("user-agent", "")
#     ip = request.client.host if request.client else "unknown"
#     return await login_confirm_controller(data, user_agent, ip)
