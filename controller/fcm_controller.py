from cores.Schema.schema_class import User
from cores.async_pg_db import SessionLocal
from schemas.fcm import FcmTokenParams, FcmUnregisterParams
from services.admin.authz import AuthError, ensure_not_banned, get_current_user
from utils.response import error, success
from utils.status_code import AuthStatus


async def _active_user_from_token(session, token: str):
    try:
        user = await get_current_user(session, token)
        ensure_not_banned(user)
        return user, None
    except AuthError as exc:
        return None, error(exc.code, exc.message)


async def register_fcm_token_controller(body: FcmTokenParams):
    async with SessionLocal() as session:
        user, auth_error = await _active_user_from_token(session, body.token)
        if auth_error:
            return auth_error
        user.fcm_token = body.fcm_token
        await session.commit()

    return success(AuthStatus.FCM_TOKEN_SAVED, "ลงทะเบียนอุปกรณ์สำเร็จ")


async def unregister_fcm_token_controller(body: FcmUnregisterParams):
    async with SessionLocal() as session:
        user, auth_error = await _active_user_from_token(session, body.token)
        if auth_error:
            return auth_error
        user.fcm_token = None
        await session.commit()

    return success(AuthStatus.FCM_TOKEN_CLEARED, "ลบการลงทะเบียนอุปกรณ์แล้ว")
