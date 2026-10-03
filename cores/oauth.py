import os
import time

import httpx
from dotenv import load_dotenv
from jose import jwk, jwt

load_dotenv()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = frozenset({"accounts.google.com", "https://accounts.google.com"})
JWKS_CACHE_SECONDS = 3600

_jwks_cache: dict = {"expires_at": 0.0, "keys": {}}


class OAuthVerificationError(Exception):
    pass


def google_audience_configured() -> bool:
    return bool(GOOGLE_CLIENT_ID)


async def _google_jwks(force: bool = False) -> dict:
    now = time.monotonic()
    if not force and _jwks_cache["keys"] and now < _jwks_cache["expires_at"]:
        return _jwks_cache["keys"]

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(GOOGLE_JWKS_URL, headers={"Accept": "application/json"})
        response.raise_for_status()
        keys = {
            key["kid"]: key
            for key in response.json().get("keys", [])
            if key.get("kid")
        }

    _jwks_cache["keys"] = keys
    _jwks_cache["expires_at"] = now + JWKS_CACHE_SECONDS
    return keys


async def verify_google_id_token(id_token: str) -> dict:
    if not GOOGLE_CLIENT_ID:
        raise OAuthVerificationError("ยังไม่ได้ตั้งค่า GOOGLE_CLIENT_ID บนเซิร์ฟเวอร์")

    try:
        header = jwt.get_unverified_header(id_token)
    except Exception as exc:
        raise OAuthVerificationError(f"รูปแบบ Google ID token ไม่ถูกต้อง: {exc}")

    key_data = (await _google_jwks()).get(header.get("kid"))
    if key_data is None:
        key_data = (await _google_jwks(force=True)).get(header.get("kid"))
    if key_data is None:
        raise OAuthVerificationError("ไม่พบกุญแจของ Google ที่ใช้เซ็น token")

    try:
        claims = jwt.decode(
            id_token,
            key=jwk.construct(key_data),
            algorithms=["RS256"],
            audience=GOOGLE_CLIENT_ID,
            options={"verify_iss": False},
        )
    except Exception as exc:
        raise OAuthVerificationError(f"ยืนยัน Google ID token ไม่สำเร็จ: {exc}")

    if claims.get("iss") not in GOOGLE_ISSUERS:
        raise OAuthVerificationError("ผู้ออก Google ID token ไม่ถูกต้อง")

    return claims
