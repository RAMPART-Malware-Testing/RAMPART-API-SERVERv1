import re

from fastapi import APIRouter, Request
from controller.auth_controller import login_confirm_controller, login_controller, register_controller, register_confirm_controller, resetPasswd_confirm_controller, resetPasswd_controller
from schemas.auth import LoginParame,  LoginConfirmParame, RegisterParame, RegisterConfirmParame, ResetPasswdParame, ResetPasswdConfirmParame
from utils.response import error

router = APIRouter(
    prefix="/api",
    tags=["Auth"]
)

EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
def is_valid_email(email: str) -> bool:
    if not email:
        return False
    return bool(re.match(EMAIL_REGEX, email))

@router.post("/login")
async def login(body: LoginParame, request: Request):
    user_agent = request.headers.get("user-agent", "")
    ip = request.client.host if request.client else "unknown"
    deviceToken = request.headers.get("deviceToken", "")
    return await login_controller(body, user_agent, ip, deviceToken)

@router.post("/login/confirm")
async def login_confirm(body: LoginConfirmParame, request: Request):
    user_agent = request.headers.get("user-agent", "")
    ip = request.client.host if request.client else "unknown"
    return await login_confirm_controller(body, user_agent, ip)

@router.post("/register")
async def register(body: RegisterParame):
    if not is_valid_email(body.email): 
        return error("VALID EMAIL ERROR","รูปแบบอีเมลไม่ถูกต้อง")
    return await register_controller(body)

@router.post("/register/confirm")
async def register_confirm(body: RegisterConfirmParame):
    return await register_confirm_controller(body)

@router.post("/reset-passwd")
async def resetpasswd(body: ResetPasswdParame):
    return await resetPasswd_controller(body)

@router.post("/reset-passwd/confirm")
async def resetpasswd_confirm(body: ResetPasswdConfirmParame):
    return await resetPasswd_confirm_controller(body)



