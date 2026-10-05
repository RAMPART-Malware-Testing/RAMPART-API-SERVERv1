"""Storing the device's FCM token on the user row.

There is no device table, so `users.fcm_token` holds one token per account.
That is a deliberate trade-off: signing in on a second phone overwrites the
first one's token and the first phone stops receiving pushes. Going beyond one
device needs either a dedicated table or a JSON array in this same column.
"""

from sqlalchemy import update

from cores.Schema.schema_class import User
from cores.async_pg_db import SessionLocal
from schemas.fcm import FcmTokenParams, FcmUnregisterParams
from services.token_service import TokenService
from utils.response import error, success
from utils.status_code import AuthStatus


async def _uid_from_token(token: str) -> str | None:
    payload, err = TokenService.verify_token(token, "access")
    if err or not payload:
        return None
    return payload.get("sub")


async def register_fcm_token_controller(body: FcmTokenParams):
    uid = await _uid_from_token(body.token)
    if not uid:
        return error(AuthStatus.TOKEN_INVALID, "โทเค็นไม่ถูกต้องหรือหมดอายุ")

    async with SessionLocal() as session:
        result = await session.execute(
            update(User).where(User.uid == uid).values(fcm_token=body.fcm_token)
        )
        if result.rowcount == 0:
            return error(AuthStatus.USER_NOT_FOUND, "ไม่พบผู้ใช้งานระบบ")
        await session.commit()

    return success(AuthStatus.FCM_TOKEN_SAVED, "ลงทะเบียนอุปกรณ์สำเร็จ")


async def unregister_fcm_token_controller(body: FcmUnregisterParams):
    """Clear the token on sign-out.

    Without this the phone keeps receiving pushes for whoever signs in next on
    the same account.
    """
    uid = await _uid_from_token(body.token)
    if not uid:
        return error(AuthStatus.TOKEN_INVALID, "โทเค็นไม่ถูกต้องหรือหมดอายุ")

    async with SessionLocal() as session:
        await session.execute(
            update(User).where(User.uid == uid).values(fcm_token=None)
        )
        await session.commit()

    return success(AuthStatus.FCM_TOKEN_CLEARED, "ลบการลงทะเบียนอุปกรณ์แล้ว")