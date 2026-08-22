from fastapi import Header, HTTPException
from utils.jwt import decode_token, get_token_subject, get_token_type
from utils.uuid import parse_uuid


def verify_access_token(token: str) -> str:
    payload = decode_token(token)

    if get_token_type(payload) != "access":
        raise ValueError("ประเภทโทเค็นไม่ถูกต้อง")

    uid = get_token_subject(payload)
    if not uid:
        raise ValueError("ข้อมูลเพย์โหลดของโทเค็นไม่ถูกต้อง")

    return uid


async def require_access_token(
    x_access_token: str | None = Header(None)
):
    if not x_access_token:
        raise HTTPException(
            status_code=401,
            detail={
                "success": False,
                "code": "ACCESS_TOKEN_MISSING",
                "message": "Access token is required"
            }
        )

    try:
        veri = verify_access_token(x_access_token)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=401,
            detail={
                "success": False,
                "code": "ACCESS_TOKEN_INVALID",
                "message": "Access token is invalid or expired"
            }
        )
    if not veri:
        raise HTTPException(
            status_code=401,
            detail={
                "success": False,
                "code": "ACCESS_TOKEN_INVALID",
                "message": "Access token is invalid or expired"
            }
        )

    try:
        return parse_uuid(veri)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=401,
            detail={
                "success": False,
                "code": "ACCESS_TOKEN_INVALID",
                "message": "Access token subject is invalid"
            }
        )
