import re

from fastapi import HTTPException, UploadFile
from fastapi.responses import FileResponse

from cores.async_pg_db import SessionLocal
from services.admin.authz import AuthError, ensure_not_banned
from services.oauth.oauth_service import user_public_dict
from services.profile.profile_service import (
    AVATAR_DIR,
    ALLOWED_IMAGE_FORMATS,
    get_user_or_404,
    update_avatar,
    update_username,
)
from services.token_service import TokenService
from utils.cache import build_suffix, cached_async, invalidate_cached
from utils.rate_limit import is_rate_limited
from utils.response import error, success
from utils.status_code import AuthStatus
from utils.uuid import parse_uuid
from sqlalchemy import select
from cores.Schema.schema_class import DownloadHistory, LoginHistory

PROFILE_CACHE_NAMESPACE = "profile:me"
PROFILE_CACHE_TTL_SECONDS = 5
DOWNLOAD_HISTORY_CACHE_NAMESPACE = "profile:download_history"
DOWNLOAD_HISTORY_CACHE_TTL_SECONDS = 5
LOGIN_HISTORY_CACHE_NAMESPACE = "profile:login_history"
LOGIN_HISTORY_CACHE_TTL_SECONDS = 5


async def record_download_controller(token: str, file_name: str | None, tool: str | None, md5: str | None):
    uid, err = _resolve_uid_or_error(token)
    if err:
        return err

    async with SessionLocal() as session:
        session.add(
            DownloadHistory(
                uid=uid,
                file_name=file_name,
                tool=tool,
                md5=md5,
            )
        )
        await session.commit()
        # build_suffix mixes uid+limit into one key, so a single-uid
        # invalidate can't target just this user's entries - clear the
        # whole (short-TTL) namespace instead.
        invalidate_cached(DOWNLOAD_HISTORY_CACHE_NAMESPACE)
        return success(AuthStatus.LOGIN_SUCCESS, "บันทึกประวัติการดาวน์โหลดสำเร็จ", None)


async def _fetch_download_history(session, uid, limit: int):
    rows = (
        await session.execute(
            select(DownloadHistory)
            .where(DownloadHistory.uid == uid)
            .order_by(DownloadHistory.created_at.desc())
            .limit(limit)
        )
    ).scalars().all()
    return [
        {
            "id": str(r.id),
            "file_name": r.file_name,
            "tool": r.tool,
            "md5": r.md5,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


async def get_download_history_controller(token: str, limit: int = 50):
    uid, err = _resolve_uid_or_error(token)
    if err:
        return err

    async with SessionLocal() as session:
        suffix = build_suffix(uid=str(uid), limit=limit)
        data = await cached_async(
            DOWNLOAD_HISTORY_CACHE_NAMESPACE,
            DOWNLOAD_HISTORY_CACHE_TTL_SECONDS,
            lambda: _fetch_download_history(session, uid, limit),
            suffix=suffix,
        )
        return success(AuthStatus.LOGIN_SUCCESS, "ดึงประวัติการดาวน์โหลดสำเร็จ", data)


async def _fetch_login_history(session, uid, limit: int):
    rows = (
        await session.execute(
            select(LoginHistory)
            .where(LoginHistory.uid == uid)
            .order_by(LoginHistory.created_at.desc())
            .limit(limit)
        )
    ).scalars().all()
    return [
        {
            "id": str(r.id),
            "provider": r.provider,
            "ip": r.ip,
            "user_agent": r.user_agent,
            "status": r.status,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


async def get_login_history_controller(token: str, limit: int = 50):
    uid, err = _resolve_uid_or_error(token)
    if err:
        return err

    async with SessionLocal() as session:
        suffix = build_suffix(uid=str(uid), limit=limit)
        data = await cached_async(
            LOGIN_HISTORY_CACHE_NAMESPACE,
            LOGIN_HISTORY_CACHE_TTL_SECONDS,
            lambda: _fetch_login_history(session, uid, limit),
            suffix=suffix,
        )
        return success(AuthStatus.LOGIN_SUCCESS, "ดึงประวัติการเข้าสู่ระบบสำเร็จ", data)

# Fixed-window caps per authenticated user (OWASP A04). Deliberately
# generous for real usage - these exist to blunt scripted abuse of an
# authenticated session, not to constrain normal editing.
_AVATAR_UPLOAD_LIMIT = 10
_AVATAR_UPLOAD_WINDOW_SECONDS = 60 * 10  # 10 requests / 10 minutes
_USERNAME_UPDATE_LIMIT = 10
_USERNAME_UPDATE_WINDOW_SECONDS = 60 * 10

# Stored avatar filenames are always `{32 hex chars}{extension}`
# (see `services.profile.profile_service._generate_avatar_token`).
# Enforcing that shape here - on top of the path-resolution check below -
# means the download route only ever serves files this API itself wrote,
# never an arbitrary name an attacker might have gotten onto disk some
# other way.
_EXTENSIONS = "|".join(re.escape(ext) for ext in ALLOWED_IMAGE_FORMATS.values())
_AVATAR_FILENAME_RE = re.compile(rf"^[0-9a-f]{{32}}(?:{_EXTENSIONS})$")

_MEDIA_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".webp": "image/webp",
}


def _resolve_uid_or_error(token: str):
    payload, err = TokenService.verify_token(token, "access")
    if err:
        return None, err
    try:
        return parse_uuid(payload["sub"]), None
    except (TypeError, ValueError, KeyError):
        return None, error(AuthStatus.TOKEN_INVALID, "ข้อมูลผู้ใช้ในโทเค็นไม่ถูกต้อง")


async def _fetch_profile(session, uid):
    user = await get_user_or_404(session, uid)
    ensure_not_banned(user)
    return user_public_dict(user)


async def get_profile_controller(token: str):
    uid, err = _resolve_uid_or_error(token)
    if err:
        return err

    async with SessionLocal() as session:
        try:
            suffix = build_suffix(uid=str(uid))
            data = await cached_async(
                PROFILE_CACHE_NAMESPACE,
                PROFILE_CACHE_TTL_SECONDS,
                lambda: _fetch_profile(session, uid),
                suffix=suffix,
            )
        except AuthError as exc:
            return error(exc.code, exc.message)
        return success(AuthStatus.LOGIN_SUCCESS, "ดึงข้อมูลโปรไฟล์สำเร็จ", data)


async def update_username_controller(token: str, username: str | None):
    uid, err = _resolve_uid_or_error(token)
    if err:
        return err
    if not username:
        return error(AuthStatus.USERNAME_TAKEN, "กรุณาระบุชื่อผู้ใช้ใหม่")

    async with SessionLocal() as session:
        user = await get_user_or_404(session, uid)
        try:
            ensure_not_banned(user)
        except AuthError as exc:
            return error(exc.code, exc.message)

    if is_rate_limited("profile:username", str(uid), _USERNAME_UPDATE_LIMIT, _USERNAME_UPDATE_WINDOW_SECONDS):
        return error(AuthStatus.RATE_LIMITED, "คุณเปลี่ยนชื่อผู้ใช้บ่อยเกินไป กรุณาลองใหม่ภายหลัง")

    async with SessionLocal() as session:
        user = await update_username(session, uid, username)
        invalidate_cached(PROFILE_CACHE_NAMESPACE)
        return success(AuthStatus.PROFILE_UPDATE_SUCCESS, "อัปเดตโปรไฟล์สำเร็จ", user_public_dict(user))


async def update_avatar_controller(token: str, file: UploadFile):
    uid, err = _resolve_uid_or_error(token)
    if err:
        return err

    async with SessionLocal() as session:
        user = await get_user_or_404(session, uid)
        try:
            ensure_not_banned(user)
        except AuthError as exc:
            return error(exc.code, exc.message)

    if is_rate_limited("profile:avatar", str(uid), _AVATAR_UPLOAD_LIMIT, _AVATAR_UPLOAD_WINDOW_SECONDS):
        return error(AuthStatus.RATE_LIMITED, "คุณอัปโหลดรูปโปรไฟล์บ่อยเกินไป กรุณาลองใหม่ภายหลัง")

    async with SessionLocal() as session:
        user = await update_avatar(session, uid, file)
        invalidate_cached(PROFILE_CACHE_NAMESPACE)
        return success(AuthStatus.AVATAR_UPDATE_SUCCESS, "อัปเดตรูปโปรไฟล์สำเร็จ", user_public_dict(user))


async def download_avatar_controller(file_name: str):
    # Reject anything that doesn't look like a filename this API generated
    # itself before ever touching the filesystem - defense in depth on top
    # of the path-resolution check (OWASP A01/A05: prevents path traversal
    # and stops the route being turned into a generic arbitrary-file server
    # for whatever else might land in AVATAR_DIR, e.g. the `.tmp` scratch
    # files written during upload).
    if not _AVATAR_FILENAME_RE.match(file_name):
        raise HTTPException(status_code=404, detail="Avatar not found")

    safe_path = (AVATAR_DIR / file_name).resolve()
    if safe_path.parent != AVATAR_DIR.resolve() or not safe_path.is_file():
        raise HTTPException(status_code=404, detail="Avatar not found")

    # Serve with the extension's known-safe media type and `nosniff` so
    # browsers never MIME-sniff stored bytes into something executable
    # (OWASP A05 - Security Misconfiguration / stored-content confusion).
    media_type = _MEDIA_TYPES.get(safe_path.suffix.lower(), "application/octet-stream")
    return FileResponse(
        path=safe_path,
        filename=safe_path.name,
        media_type=media_type,
        headers={
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": "inline",
            "Cache-Control": "private, max-age=86400",
        },
    )
