from fastapi import HTTPException
from fastapi.requests import Request

from cores.async_pg_db import SessionLocal
from cores.oauth import oauth, oauth_configured, redirect_uri_for
from services.oauth.oauth_service import (
    OAuthError,
    fetch_github_profile,
    fetch_google_profile,
    find_or_create_user,
    issue_access_token,
    user_public_dict,
)
from utils.response import error, success
from utils.status_code import AuthStatus

_PROFILE_FETCHERS = {
    "google": fetch_google_profile,
    "github": fetch_github_profile,
}


def _require_supported_provider(provider: str) -> None:
    if provider not in _PROFILE_FETCHERS:
        raise HTTPException(status_code=404, detail="Unsupported OAuth provider")
    if not oauth_configured(provider):
        raise HTTPException(
            status_code=503,
            detail=f"{provider.title()} OAuth is not configured on this server. "
            f"Set the corresponding client id/secret in .env.",
        )


async def oauth_login_controller(request: Request, provider: str):
    _require_supported_provider(provider)
    client = oauth.create_client(provider)
    redirect_uri = redirect_uri_for(provider)
    return await client.authorize_redirect(request, redirect_uri)


async def oauth_callback_controller(request: Request, provider: str):
    _require_supported_provider(provider)
    client = oauth.create_client(provider)

    try:
        token = await client.authorize_access_token(request)
    except Exception as exc:  # authlib raises provider-specific OAuthError subclasses
        return error(AuthStatus.OAUTH_PROVIDER_ERROR, f"OAuth authorization failed: {exc}")

    try:
        profile = await _PROFILE_FETCHERS[provider](token)
    except OAuthError as exc:
        return error(AuthStatus.OAUTH_EMAIL_MISSING, str(exc))

    async with SessionLocal() as session:
        user = await find_or_create_user(session, profile)

    access_token = issue_access_token(user)

    return success(
        AuthStatus.LOGIN_SUCCESS,
        "เข้าสู่ระบบด้วย OAuth สำเร็จ",
        {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": 60 * 60 * 24 * 7,
            "data": user_public_dict(user),
        },
    )
