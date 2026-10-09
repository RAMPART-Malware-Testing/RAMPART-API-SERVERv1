import re
import secrets
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cores.Schema.schema_class import OAuthAccount, User
from utils.email_normalize import normalize_email, normalized_email_expr
from utils.jwt import create_token

ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

_USERNAME_SANITIZE_RE = re.compile(r"[^a-zA-Z0-9_.-]")

@dataclass(frozen=True)
class OAuthProfile:
    provider: str
    provider_uid: str
    email: str
    email_verified: bool
    display_name: str | None

class OAuthError(Exception):
    pass

def profile_from_bridge_payload(payload: dict) -> OAuthProfile:
    return OAuthProfile(
        provider=payload["provider"],
        provider_uid=str(payload["sub"]),
        email=payload["email"].lower(),
        email_verified=bool(payload.get("email_verified", False)),
        display_name=payload.get("display_name") or None,
    )

async def _generate_unique_username(session: AsyncSession, seed: str) -> str:
    base = _USERNAME_SANITIZE_RE.sub("", seed.split("@")[0]).strip(".-_") or "user"
    base = base[:40] or "user"

    candidate = base
    while True:
        result = await session.execute(select(User.uid).where(User.username == candidate))
        if result.scalar_one_or_none() is None:
            return candidate
        candidate = f"{base}-{secrets.token_hex(3)}"[:50]

async def find_or_create_user(session: AsyncSession, profile: OAuthProfile) -> User:
    linked = await session.execute(
        select(OAuthAccount).where(
            OAuthAccount.provider == profile.provider,
            OAuthAccount.provider_uid == profile.provider_uid,
        )
    )
    oauth_account = linked.scalar_one_or_none()
    if oauth_account is not None:
        user = await session.get(User, oauth_account.uid)
        if user is not None:
            if (user.status or "").lower() != "active":
                raise OAuthError("This account is not active.")
            return user

    existing_user_result = await session.execute(
        select(User).where(normalized_email_expr(User.email) == normalize_email(profile.email))
    )
    user = existing_user_result.scalar_one_or_none()

    if user is None:
        username = await _generate_unique_username(session, profile.display_name or profile.email)
        user = User(
            username=username,
            email=profile.email,
            avatar_url=None,
            role="user",
            status="active",
        )
        session.add(user)
        await session.flush()
    else:
        if (user.status or "").lower() != "active":
            raise OAuthError("This account is not active.")
        if not profile.email_verified:
            raise OAuthError(
                "This e-mail is already registered with a different sign-in "
                "method and the provider did not verify this address."
            )

    session.add(
        OAuthAccount(
            uid=user.uid,
            provider=profile.provider,
            provider_uid=profile.provider_uid,
            provider_email=profile.email,
        )
    )
    await session.commit()
    await session.refresh(user)
    return user

def issue_access_token(user: User) -> str:
    return create_token(
        subject=str(user.uid),
        token_type="access",
        expires_minutes=ACCESS_TOKEN_EXPIRE_MINUTES,
        extra_payload={
            "username": user.username,
            "role": user.role,
        },
    )

DEVICE_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

def issue_device_token(user: User) -> str:
    return create_token(
        subject=str(user.uid),
        token_type="device",
        expires_minutes=DEVICE_TOKEN_EXPIRE_MINUTES,
        extra_payload={"email": user.email},
    )

def user_public_dict(user: User) -> dict:
    return {
        "uid": str(user.uid),
        "username": user.username,
        "email": user.email,
        "avatar_url": user.avatar_url,
        "role": user.role,
        "status": user.status,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }
