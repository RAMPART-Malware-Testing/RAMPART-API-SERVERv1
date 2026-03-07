from fastapi import Header, HTTPException
from services.auth.auth_service import verify_access_token

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

    veri = verify_access_token(x_access_token)
    if not veri:
        raise HTTPException(
            status_code=401,
            detail={
                "success": False,
                "code": "ACCESS_TOKEN_INVALID",
                "message": "Access token is invalid or expired"
            }
        )

    return int(veri)
