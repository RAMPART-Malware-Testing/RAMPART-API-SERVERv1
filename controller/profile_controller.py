from fastapi import HTTPException, UploadFile
from fastapi.responses import FileResponse

from cores.async_pg_db import SessionLocal
from services.oauth.oauth_service import user_public_dict
from services.profile.profile_service import AVATAR_DIR, get_user_or_404, update_avatar, update_username
from services.token_service import TokenService
from utils.response import error, success
from utils.status_code import AuthStatus
from utils.uuid import parse_uuid


def _resolve_uid_or_error(token: str):
    payload, err = TokenService.verify_token(token, "access")
    if err:
        return None, err
    try:
        return parse_uuid(payload["sub"]), None
    except (TypeError, ValueError, KeyError):
        return None, error(AuthStatus.TOKEN_INVALID, "ข้อมูลผู้ใช้ในโทเค็นไม่ถูกต้อง")


async def get_profile_controller(token: str):
    uid, err = _resolve_uid_or_error(token)
    if err:
        return err

    async with SessionLocal() as session:
        user = await get_user_or_404(session, uid)
        return success(AuthStatus.LOGIN_SUCCESS, "ดึงข้อมูลโปรไฟล์สำเร็จ", user_public_dict(user))


async def update_username_controller(token: str, username: str | None):
    uid, err = _resolve_uid_or_error(token)
    if err:
        return err
    if not username:
        return error(AuthStatus.USERNAME_TAKEN, "กรุณาระบุชื่อผู้ใช้ใหม่")

    async with SessionLocal() as session:
        user = await update_username(session, uid, username)
        return success(AuthStatus.PROFILE_UPDATE_SUCCESS, "อัปเดตโปรไฟล์สำเร็จ", user_public_dict(user))


async def update_avatar_controller(token: str, file: UploadFile):
    uid, err = _resolve_uid_or_error(token)
    if err:
        return err

    async with SessionLocal() as session:
        user = await update_avatar(session, uid, file)
        return success(AuthStatus.AVATAR_UPDATE_SUCCESS, "อัปเดตรูปโปรไฟล์สำเร็จ", user_public_dict(user))


async def download_avatar_controller(file_name: str):
    safe_path = (AVATAR_DIR / file_name).resolve()
    if safe_path.parent != AVATAR_DIR.resolve() or not safe_path.is_file():
        raise HTTPException(status_code=404, detail="Avatar not found")
    return FileResponse(path=safe_path, filename=safe_path.name)
