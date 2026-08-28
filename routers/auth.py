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
from controller.oauth_controller import oauth_callback_controller, oauth_login_controller
from schemas.auth import (
    LoginConfirmParame,
    LoginParame,
    RefreshTokenParame,
    RegisterConfirmParame,
    RegisterParame,
    ResetPasswdConfirmParame,
    ResetPasswdParame,
)

router = APIRouter(prefix="/api/auth", tags=["Auth"])

@router.get("/{provider}/login")
async def oauth_login(provider: str, request: Request):
    """Redirects the browser to Google/GitHub's consent screen.

    provider: "google" | "github"
    """
    return await oauth_login_controller(request, provider)

@router.get("/{provider}/callback")
async def oauth_callback(provider: str, request: Request):
    """Google/GitHub redirects back here after the user grants access.

    On success this issues the same `access` JWT the rest of the API already
    expects (7 day expiry). Signing in again with the same provider account
    always resolves to the same `uid`.
    """
    return await oauth_callback_controller(request, provider)

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