"""Business logic for Google / GitHub OAuth login.

OAuth is one of two supported ways to authenticate (the other being local
email+password with OTP confirmation, see services/auth/auth_service.py) -
both resolve to the same `users` row and share the same `role`/`is_banned`
access-control state. A user who signs in only via OAuth has `password IS
NULL` on their row; AuthService.login() checks for that and rejects
password-login for such accounts rather than crashing. The only job of this
service is:

1. Ask the provider "who is this?" (via `fetch_google_profile` /
   `fetch_github_profile`), normalized to a small `OAuthProfile`.
2. Resolve that profile to a `users` row - creating one on first login,
   reusing the same `uid` on every login after that - via
   `find_or_create_user`.
3. Issue the same kind of `access` JWT the rest of the API already expects.
"""

import os
import re
import secrets
from dataclasses import dataclass

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cores.Schema.schema_class import OAuthAccount, User
from utils.email_normalize import normalize_email, normalized_email_expr
from utils.jwt import create_token

ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

_USERNAME_SANITIZE_RE = re.compile(r"[^a-zA-Z0-9_.-]")

ROOT_EMAIL = os.getenv("ROOT_EMAIL", "").strip().lower()

@dataclass(frozen=True)
class OAuthProfile:
    provider: str
    provider_uid: str
    email: str
    email_verified: bool
    display_name: str | None

class OAuthError(Exception):
    """Raised when the provider callback can't be trusted (e.g. no verified e-mail)."""

async def fetch_google_profile(token: dict) -> OAuthProfile:
    userinfo = token.get("userinfo")
    if not userinfo:
        from cores.oauth import oauth

        userinfo = await oauth.google.userinfo(token=token)

    email = userinfo.get("email")
    if not email:
        raise OAuthError("Google account did not return an e-mail address.")

    return OAuthProfile(
        provider="google",
        provider_uid=str(userinfo["sub"]),
        email=email.lower(),
        email_verified=bool(userinfo.get("email_verified", False)),
        display_name=userinfo.get("name") or userinfo.get("given_name"),
    )

async def fetch_github_profile(token: dict) -> OAuthProfile:
    from cores.oauth import oauth

    profile_resp = await oauth.github.get("user", token=token)
    profile_resp.raise_for_status()
    profile = profile_resp.json()

    email = profile.get("email")
    email_verified = True if email else False

    if not email:
        emails_resp = await oauth.github.get("user/emails", token=token)
        emails_resp.raise_for_status()
        emails = emails_resp.json()
        primary = next((e for e in emails if e.get("primary") and e.get("verified")), None)
        if primary is None:
            primary = next((e for e in emails if e.get("verified")), None)
        if primary is None:
            raise OAuthError("GitHub account has no verified e-mail address.")
        email = primary["email"]
        email_verified = True

    return OAuthProfile(
        provider="github",
        provider_uid=str(profile["id"]),
        email=email.lower(),
        email_verified=email_verified,
        display_name=profile.get("name") or profile.get("login"),
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
    - E-mail matches ROOT_EMAIL (.env) -> always role="master" and never
      banned, enforced on every login (new account, an existing one that
      drifted away from master, or one that was somehow left banned).
    """
    is_root = bool(ROOT_EMAIL) and profile.email.lower() == ROOT_EMAIL

    def _reconfirm_root(u: User) -> bool:
        """Self-heal the root account's role/ban state. Returns True if a
        commit is needed."""
        changed = False
        if u.role != "master":
            u.role = "master"
            changed = True
        if u.is_banned:
            u.is_banned = False
            u.banned_at = None
            u.banned_reason = None
            u.banned_by = None
            changed = True
        return changed

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
            if is_root and _reconfirm_root(user):
                await session.commit()
                await session.refresh(user)
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
            role="master" if is_root else "user",
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
        if is_root:
            _reconfirm_root(user)

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
