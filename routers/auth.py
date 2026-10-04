from fastapi import APIRouter, Header, Request

from controller.auth_controller import (
    first_run_setup_controller,
    first_run_status_controller,
    login_confirm_controller,
    login_controller,
    refresh_token_controller,
    register_confirm_controller,
    register_controller,
    resetPasswd_confirm_controller,
    resetPasswd_controller,
)
from controller.oauth_controller import oauth_bridge_controller
from schemas.auth import (
    BridgeTokenParame,
    FirstRunSetupParame,
    LoginConfirmParame,
    LoginParame,
    RefreshTokenParame,
    RegisterConfirmParame,
    RegisterParame,
    ResetPasswdConfirmParame,
    ResetPasswdParame,
)

router = APIRouter(prefix="/api/auth", tags=["Auth"])

@router.get("/setup/status")
async def first_run_status():
    """Reports whether the first master account still needs to be created.

    Unauthenticated by design - the web app calls it to decide between the
    setup page and the login page. Returns one boolean and nothing else.
    """
    return await first_run_status_controller()

@router.post("/setup/complete")
async def first_run_setup(body: FirstRunSetupParame, request: Request):
    """Creates the first master account. Works only while `users` is empty.

    Unauthenticated - there is no account to authenticate as until this call
    succeeds. See services/auth/first_run_setup.py.
    """
    forwarded = request.headers.get("x-forwarded-for")
    ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")
    return await first_run_setup_controller(body, ip)

@router.post("/{provider}/bridge")
async def oauth_bridge(provider: str, body: BridgeTokenParame, request: Request):
    """Turns a bridge token into the same `access` JWT the rest of the API expects.

    The web application owns the provider OAuth flow: it runs the redirect,
    exchanges the authorization code, and verifies the credential it gets back
    (Google's ID token against Google's signing keys, GitHub's access token
    against the GitHub API). Only then does it state the result here as a
    short-lived HS256 token signed with OAUTH_BRIDGE_SECRET.

    This endpoint therefore trusts the web app completely - it never sees a
    Google client ID, a redirect URI or a provider token, and it only stores
    the user record it ends up with.

    provider: "google" | "github" - must match the provider inside the token.
    """
    ua = request.headers.get("user-agent")
    ip = request.client.host if request.client else None
    return await oauth_bridge_controller(provider, body, ua, ip)

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