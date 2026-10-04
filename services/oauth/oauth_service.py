"""Business logic for Google / GitHub OAuth login.

The web application runs the provider OAuth flow end to end: it exchanges the
authorization code, verifies Google's ID token against Google's signing keys,
asks GitHub who the user is, and only then states the outcome to this service
as a bridge token (see cores/bridge.py). What arrives here is therefore an
already-verified claim, normalised to a small `OAuthProfile`, resolved to a
`users` row by `find_or_create_user`, and answered with the same kind of
`access` JWT the rest of the API already expects.

This service stores user records and issues its own tokens. It never sees an
OAuth client secret, a redirect URI or a provider access token.
"""

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
    """Raised when the provider callback can't be trusted (e.g. no verified e-mail)."""

def profile_from_bridge_payload(payload: dict) -> OAuthProfile:
    """Normalise verified bridge-token claims into an `OAuthProfile`.

    `cores.bridge.verify_bridge_token` has already checked the signature, the
    expiry, the token type and the presence of `sub`/`email` by the time a
    payload gets here, so this only shapes it.
    """
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
    """Resolve a provider profile to a durable `users` row.

    - Same (provider, provider_uid) seen again -> same uid, every time.
    - New provider but an existing verified e-mail -> link the new provider
      to that existing account instead of creating a duplicate user.
    - Otherwise -> brand-new account, avatar_url stays NULL until the user
      explicitly uploads a profile picture.

    Accounts created here always get role="user". `master` is granted by
    exactly one path - the first-run setup endpoint - so that a provider
    login can never produce an administrator, and so that "setup happens
    once" stays true regardless of who signs in first.
    """

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
        "must_setup": bool(user.must_setup),
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }
