from fastapi import HTTPException
from fastapi.requests import Request

from cores.async_pg_db import SessionLocal
from cores.oauth import OAuthVerificationError, google_audience_configured
from cores.Schema.schema_class import LoginHistory
from schemas.auth import OAuthExchangeParame
from services.oauth.oauth_service import (
    OAuthError,
    find_or_create_user,
    issue_access_token,
    issue_device_token,
    profile_from_github_access_token,
    profile_from_google_id_token,
    user_public_dict,
)
from utils.response import error, success
from utils.status_code import AuthStatus

SUPPORTED_PROVIDERS = ("google", "github")

def _require_supported_provider(provider: str) -> None:
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=404, detail="Unsupported OAuth provider")
    if provider == "google" and not google_audience_configured():
        raise HTTPException(
            status_code=503,
            detail="Google audience is not configured on this server. Set GOOGLE_CLIENT_ID in .env.",
        )

async def _resolve_profile(provider: str, body: OAuthExchangeParame):
    if provider == "google":
        if not body.id_token:
            raise OAuthError("ไม่พบ Google ID token")
        return await profile_from_google_id_token(body.id_token)
    if not body.access_token:
        raise OAuthError("ไม่พบ GitHub access token")
    return await profile_from_github_access_token(body.access_token)

async def oauth_exchange_controller(provider: str, body: OAuthExchangeParame, user_agent: str | None, ip: str | None):
    _require_supported_provider(provider)

    try:
        profile = await _resolve_profile(provider, body)
    except OAuthError as exc:
        return error(AuthStatus.OAUTH_PROVIDER_ERROR, str(exc))
    except OAuthVerificationError as exc:
        return error(AuthStatus.OAUTH_PROVIDER_ERROR, str(exc))
    except Exception as exc:
        return error(AuthStatus.OAUTH_PROVIDER_ERROR, f"ยืนยันตัวตนจาก {provider} ไม่สำเร็จ: {exc}")

    try:
        async with SessionLocal() as session:
            user = await find_or_create_user(session, profile)
    except OAuthError as exc:
        return error(AuthStatus.OAUTH_ACCOUNT_LINKED, str(exc))

    try:
        async with SessionLocal() as session:
            session.add(
                LoginHistory(
                    uid=user.uid,
                    provider=profile.provider,
                    ip=ip,
                    user_agent=user_agent,
                    status="success",
                )
            )
            await session.commit()
    except Exception as exc:
        print(f"[LoginHistory] Failed to record login for {user.uid}: {exc}")

    return success(
        AuthStatus.LOGIN_SUCCESS,
        "เข้าสู่ระบบสำเร็จ",
        {
            "access_token": issue_access_token(user),
            "device_token": issue_device_token(user),
            "data": user_public_dict(user),
        },
    )