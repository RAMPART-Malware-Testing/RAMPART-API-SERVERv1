import re

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from cores.async_pg_db import SessionLocal
from cores.models_class import User
from controller.auth_controller import login_confirm_controller, login_controller, refresh_token_controller, register_controller, register_confirm_controller, resetPasswd_confirm_controller, resetPasswd_controller
from schemas.auth import LoginParame,  LoginConfirmParame, RefreshTokenParame, RegisterParame, RegisterConfirmParame, ResetPasswdParame, ResetPasswdConfirmParame
from services.token_service import TokenService
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

@router.post("/refresh-token")
async def refresh_token(body: RefreshTokenParame):
    return await refresh_token_controller(body.refresh_token)


class FCMRegisterRequest(BaseModel):
    fcm_token: str


@router.post("/fcm/register")
async def register_fcm_token(
    body: FCMRegisterRequest,
    x_access_token: str = Header(...),
):
    payload, err = TokenService.verify_token(x_access_token, "access")
    if err:
        raise HTTPException(status_code=401, detail="Invalid access token")

    uid = int(payload["sub"])
    async with SessionLocal() as session:
        result = await session.execute(select(User).where(User.uid == uid))
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user.fcm_token = body.fcm_token
        await session.commit()

    return {"success": True, "message": "ลงทะเบียน FCM token สำเร็จ"}
