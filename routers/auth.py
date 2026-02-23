from fastapi import APIRouter, Request
from controller.auth_controller import access_token_controller, login_confirm_controller, login_controller, register_controller, register_confirm_controller
from schemas.auth import LoginParame,  LoginConfirmParame, RegisterParame, RegisterConfirmParame, ResetPasswdParame, ResetPasswdConfirmParame
from services.auth_service import verify_access_token

router = APIRouter(
    prefix="/api",
    tags=["Auth"]
)

@router.post("/login")
async def login(body: LoginParame, request: Request):
    user_agent = request.headers.get("user-agent", "")
    ip = request.client.host if request.client else "unknown"
    return await login_controller(body, user_agent, ip)

@router.post("/login/confirm")
async def login_confirm(data: LoginConfirmParame, request: Request):
    user_agent = request.headers.get("user-agent", "")
    ip = request.client.host if request.client else "unknown"
    return await login_confirm_controller(data, user_agent, ip)

@router.post("/register")
async def login_confirm(body: RegisterParame):
    return await register_controller(body)

@router.post("/register/confirm")
async def login_confirm(body: RegisterConfirmParame):
    return await register_confirm_controller(body)

@router.post("/reset-passwd")
async def login_confirm(data: ResetPasswdParame, request: Request):
    user_agent = request.headers.get("user-agent", "")
    ip = request.client.host if request.client else "unknown"
    return await login_confirm_controller(data, user_agent, ip)

@router.post("/reset-passwd/confirm")
async def login_confirm(data: ResetPasswdConfirmParame, request: Request):
    user_agent = request.headers.get("user-agent", "")
    ip = request.client.host if request.client else "unknown"
    return await login_confirm_controller(data, user_agent, ip)

# @router.post("/login/access")
# async def access_token(data: AccessToken):
#     try:
#         user = verify_access_token(data.token)
#     except ValueError as e:
#         return {
#             "success": False,
#             "message": str(e)
#         }
#     return await access_token_controller(user)