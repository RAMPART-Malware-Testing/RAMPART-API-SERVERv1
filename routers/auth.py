from fastapi import APIRouter, Header, Request

from controller.auth_controller import (
    login_confirm_controller,
    login_controller,
    refresh_token_controller,
    register_confirm_controller,
    register_controller,
    resetPasswd_confirm_controller,
    resetPasswd_controller,
)
from controller.oauth_controller import oauth_exchange_controller
from schemas.auth import (
    LoginConfirmParame,
    LoginParame,
    OAuthExchangeParame,
    RefreshTokenParame,
    RegisterConfirmParame,
    RegisterParame,
    ResetPasswdConfirmParame,
    ResetPasswdParame,
)

router = APIRouter(prefix="/api/auth", tags=["Auth"])

@router.post("/{provider}/exchange")
async def oauth_exchange(provider: str, body: OAuthExchangeParame, request: Request):
    """Verifies a provider credential produced by the web application's own
    OAuth flow and issues the same `access` JWT the rest of the API expects.

    provider: "google" | "github"
    google: `id_token`   github: `access_token`
    """
    ua = request.headers.get("user-agent")
    ip = request.client.host if request.client else None
    return await oauth_exchange_controller(provider, body, ua, ip)

@router.post("/login")
async def login(body: LoginParame, request: Request, deviceToken: str = Header("")):
    ua = request.headers.get("user-agent")
    ip = request.client.host if request.client else None
    return await login_controller(body, ua, ip, deviceToken)

@router.post("/login/confirm")
async def login_confirm(body: LoginConfirmParame, request: Request):
    ua = request.headers.get("user-agent")
    ip = request.client.host if request.client else None
    return await login_confirm_controller(body, ua, ip)

@router.post("/register")
async def register(body: RegisterParame):
    return await register_controller(body)

@router.post("/register/confirm")
async def register_confirm(body: RegisterConfirmParame):
    return await register_confirm_controller(body)

@router.post("/reset-passwd")
async def reset_passwd(body: ResetPasswdParame):
    return await resetPasswd_controller(body)

@router.post("/reset-passwd/confirm")
async def reset_passwd_confirm(body: ResetPasswdConfirmParame):
    return await resetPasswd_confirm_controller(body)

@router.post("/refresh")
async def refresh(body: RefreshTokenParame):
    return await refresh_token_controller(body.refresh_token)