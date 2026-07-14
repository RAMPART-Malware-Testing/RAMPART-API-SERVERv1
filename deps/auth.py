from fastapi import Header, HTTPException
from services.auth.auth_service import verify_access_token
from utils.uuid import parse_uuid

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
