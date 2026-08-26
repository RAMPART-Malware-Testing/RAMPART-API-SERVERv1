from urllib.parse import urlencode

from fastapi import HTTPException
from fastapi.requests import Request
from fastapi.responses import RedirectResponse

from cores.async_pg_db import SessionLocal
from cores.oauth import FRONTEND_URL, oauth, oauth_configured, redirect_uri_for
from cores.Schema.schema_class import LoginHistory
from services.oauth.oauth_service import (
    OAuthError,
    fetch_github_profile,
    fetch_google_profile,
    find_or_create_user,
    issue_access_token,
    issue_device_token,
    user_public_dict,
)
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


def _frontend_redirect(path: str, **params) -> RedirectResponse:
    query = urlencode({k: v for k, v in params.items() if v is not None})
    url = f"{FRONTEND_URL}{path}"
    if query:
        url = f"{url}?{query}"
    return RedirectResponse(url, status_code=302)


async def oauth_login_controller(request: Request, provider: str):
    _require_supported_provider(provider)
    client = oauth.create_client(provider)
    redirect_uri = redirect_uri_for(provider)
    return await client.authorize_redirect(request, redirect_uri)


async def oauth_callback_controller(request: Request, provider: str):
    """Finishes the OAuth dance and hands control back to the browser.

    This is reached by the browser being redirected here by Google/GitHub,
    so it can't just return JSON - the caller has no way to read a fetch
    response. Instead it always ends in a 302 back to the Next.js app:
      - success -> {FRONTEND_URL}/auth/callback?access_token=...&expires_in=...
      - failure -> {FRONTEND_URL}/login?error=<code>&message=<text>
    The frontend's /auth/callback route is what actually persists the
    session (as its own httpOnly cookie) and fetches the profile.
    """
    _require_supported_provider(provider)
    client = oauth.create_client(provider)

    try:
        token = await client.authorize_access_token(request)
    except Exception as exc:  # authlib raises provider-specific OAuthError subclasses
        return _frontend_redirect(
            "/login",
            error=AuthStatus.OAUTH_PROVIDER_ERROR,
            message=f"OAuth authorization failed: {exc}",
        )

    try:
        profile = await _PROFILE_FETCHERS[provider](token)
    except OAuthError as exc:
        return _frontend_redirect(
            "/login",
            error=AuthStatus.OAUTH_EMAIL_MISSING,
            message=str(exc),
        )

    try:
        async with SessionLocal() as session:
            user = await find_or_create_user(session, profile)
    except OAuthError as exc:
        return _frontend_redirect(
            "/login",
            error=AuthStatus.OAUTH_EMAIL_MISSING,
            message=str(exc),
        )

    access_token = issue_access_token(user)
    device_token = issue_device_token(user)

    # Record the login for the profile "ประวัติการเข้าสู่ระบบ" tab.
    try:
        async with SessionLocal() as session:
            session.add(
                LoginHistory(
                    uid=user.uid,
                    provider=profile.provider,
                    ip=request.client.host if request.client else None,
                    user_agent=request.headers.get("user-agent"),
                    status="success",
                )
            )
            await session.commit()
    except Exception as exc:
        print(f"[LoginHistory] Failed to record login for {user.uid}: {exc}")

    return _frontend_redirect(
        "/auth/callback",
        access_token=access_token,
        token_type="bearer",
        expires_in=60 * 60 * 24 * 7,
        device_token=device_token,
    )
