"""Verification of the short-lived bridge token the web app hands us.

The web application runs the entire provider OAuth flow. Once it has verified
Google's ID token against Google's signing keys, or asked GitHub who the user
is, it states the result as a token this service can check on its own: an
HS256 JWT signed with OAUTH_BRIDGE_SECRET.

That secret is the entire trust boundary. Whoever holds it can assert any
identity here, so it never leaves the web app, and the token's lifetime is
measured in minutes rather than days - it exists only to cross one hop, not to
hold a session.
"""

import os

from jose import jwt, JWTError

BRIDGE_SECRET = os.getenv("OAUTH_BRIDGE_SECRET", "").strip()
BRIDGE_ALGORITHM = "HS256"
BRIDGE_TYPE = "oauth_bridge"
SUPPORTED_PROVIDERS = ("google", "github")

# Ceiling on the token's own lifetime. The web app issues these with a shorter
# TTL; this is the backstop for a token that somehow arrives already stale.
BRIDGE_MAX_AGE_SECONDS = 120


class BridgeTokenError(Exception):
    """Raised when a bridge token is missing, forged, expired or malformed."""


def bridge_configured() -> bool:
    return bool(BRIDGE_SECRET)


def verify_bridge_token(token: str) -> dict:
    """Return the verified claims, or raise BridgeTokenError."""
    if not BRIDGE_SECRET:
        raise BridgeTokenError(
            "ยังไม่ได้ตั้งค่า OAUTH_BRIDGE_SECRET บนเซิร์ฟเวอร์ "
            "(ต้องตรงกับค่าที่เว็บแอปใช้เซ็น)"
        )

    try:
        payload = jwt.decode(
            token,
            BRIDGE_SECRET,
            algorithms=[BRIDGE_ALGORITHM],
            options={"require_exp": True},
        )
    except JWTError as exc:
        raise BridgeTokenError(f"ยืนยัน bridge token ไม่สำเร็จ: {exc}")

    if payload.get("type") != BRIDGE_TYPE:
        raise BridgeTokenError("bridge token นี้ไม่ได้ถูกออกมาเพื่อเข้าสู่ระบบ")

    provider = payload.get("provider")
    if provider not in SUPPORTED_PROVIDERS:
        raise BridgeTokenError(f"ไม่รองรับผู้ให้บริการ OAuth: {provider}")

    provider_uid = payload.get("sub")
    if not isinstance(provider_uid, str) or not provider_uid:
        raise BridgeTokenError("bridge token ไม่มีรหัสประจำตัวจากผู้ให้บริการ")

    email = payload.get("email")
    if not isinstance(email, str) or not email:
        raise BridgeTokenError("bridge token ไม่มีที่อยู่อีเมล")

    return payload