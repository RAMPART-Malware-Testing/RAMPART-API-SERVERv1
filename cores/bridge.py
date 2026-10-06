import os

from jose import jwt, JWTError

BRIDGE_SECRET = os.getenv("OAUTH_BRIDGE_SECRET", "").strip()
BRIDGE_ALGORITHM = "HS256"
BRIDGE_TYPE = "oauth_bridge"
SUPPORTED_PROVIDERS = ("google", "github")


class BridgeTokenError(Exception):
    pass


def bridge_configured() -> bool:
    return bool(BRIDGE_SECRET)


def verify_bridge_token(token: str) -> dict:
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