from fastapi import HTTPException

from cores.async_pg_db import SessionLocal
from cores.bridge import BridgeTokenError, verify_bridge_token
from cores.Schema.schema_class import LoginHistory
from schemas.auth import BridgeTokenParame
from services.oauth.oauth_service import (
    OAuthError,
    find_or_create_user,
    issue_access_token,
    issue_device_token,
    profile_from_bridge_payload,
    user_public_dict,
)
from utils.response import error, success
from utils.status_code import AuthStatus

SUPPORTED_PROVIDERS = ("google", "github")


async def oauth_bridge_controller(
    provider: str,
    body: BridgeTokenParame,
    user_agent: str | None,
    ip: str | None,
):
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=404, detail="Unsupported OAuth provider")

    try:
        payload = verify_bridge_token(body.bridge_token)
    except BridgeTokenError as exc:
        return error(AuthStatus.OAUTH_PROVIDER_ERROR, str(exc))

    if payload.get("provider") != provider:
        return error(
            AuthStatus.OAUTH_PROVIDER_ERROR,
            "bridge token ไม่ตรงกับผู้ให้บริการที่ร้องขอ",
        )

    profile = profile_from_bridge_payload(payload)

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