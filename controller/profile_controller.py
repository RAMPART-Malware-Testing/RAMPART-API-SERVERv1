import json
import re

from fastapi import HTTPException, UploadFile
from fastapi.responses import FileResponse

from cores.async_pg_db import SessionLocal
from services.admin.admin_service import write_audit_log
from services.admin.authz import AuthError, ensure_not_banned
from services.oauth.oauth_service import user_public_dict
from services.profile.email_change import (
    confirm_email_change,
    resend_email_otp,
    start_email_change,
    verify_old_email_otp,
)
from services.profile.profile_service import (
    AVATAR_DIR,
    ALLOWED_IMAGE_FORMATS,
    change_password,
    get_user_or_404,
    unread_notification_counts,
    update_avatar,
    update_username,
)
from services.token_service import TokenService
from utils.cache import build_suffix, cached_async, invalidate_cached
from utils.rate_limit import is_rate_limited
from utils.response import error, success
from utils.status_code import AuthStatus
from utils.uuid import parse_uuid
from sqlalchemy import func, select
from cores.Schema.schema_class import AuditLog, DownloadHistory, LoginHistory
from schemas.profile import HISTORY_DEFAULT_LIMIT, HISTORY_MAX_LIMIT

PASSWORD_CHANGE_AUDIT_ACTION = "change_password"

PROFILE_CACHE_NAMESPACE = "profile:me"
PROFILE_CACHE_TTL_SECONDS = 5
DOWNLOAD_HISTORY_CACHE_NAMESPACE = "profile:download_history"
DOWNLOAD_HISTORY_CACHE_TTL_SECONDS = 5
LOGIN_HISTORY_CACHE_NAMESPACE = "profile:login_history"
LOGIN_HISTORY_CACHE_TTL_SECONDS = 5
PASSWORD_HISTORY_CACHE_NAMESPACE = "profile:password_history"
PASSWORD_HISTORY_CACHE_TTL_SECONDS = 5

def _normalize_page_params(page: int, limit: int) -> tuple[int, int]:
    return max(1, page), min(max(1, limit), HISTORY_MAX_LIMIT)

def _pagination_meta(page: int, limit: int, total: int) -> dict:
    total_pages = max(1, -(-total // limit))
    return {
        "page": page,
        "limit": limit,
        "total": total,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1,
    }

def _history_response(message: str, result: dict) -> dict:
    return {
        **success(AuthStatus.LOGIN_SUCCESS, message, result["data"]),
        "pagination": result["pagination"],
    }

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
        invalidate_cached(DOWNLOAD_HISTORY_CACHE_NAMESPACE)
        return success(AuthStatus.LOGIN_SUCCESS, "บันทึกประวัติการดาวน์โหลดสำเร็จ", None)

async def _fetch_download_history(session, uid, page: int, limit: int):
    total = (
        await session.execute(
            select(func.count()).select_from(DownloadHistory).where(DownloadHistory.uid == uid)
        )
    ).scalar_one()
    rows = (
        await session.execute(
            select(DownloadHistory)
            .where(DownloadHistory.uid == uid)
            .order_by(DownloadHistory.created_at.desc())
            .offset((page - 1) * limit)
            .limit(limit)
        )
    ).scalars().all()
    return {
        "data": [
            {
                "id": str(r.id),
                "file_name": r.file_name,
                "tool": r.tool,
                "md5": r.md5,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
        "pagination": _pagination_meta(page, limit, int(total)),
    }

async def get_download_history_controller(
    token: str, page: int = 1, limit: int = HISTORY_DEFAULT_LIMIT
):
    uid, err = _resolve_uid_or_error(token)
    if err:
        return err
    page, limit = _normalize_page_params(page, limit)

    async with SessionLocal() as session:
        suffix = build_suffix(uid=str(uid), page=page, limit=limit)
        result = await cached_async(
            DOWNLOAD_HISTORY_CACHE_NAMESPACE,
            DOWNLOAD_HISTORY_CACHE_TTL_SECONDS,
            lambda: _fetch_download_history(session, uid, page, limit),
            suffix=suffix,
        )
        return _history_response("ดึงประวัติการดาวน์โหลดสำเร็จ", result)

async def _fetch_login_history(session, uid, page: int, limit: int):
    total = (
        await session.execute(
            select(func.count()).select_from(LoginHistory).where(LoginHistory.uid == uid)
        )
    ).scalar_one()
    rows = (
        await session.execute(
            select(LoginHistory)
            .where(LoginHistory.uid == uid)
            .order_by(LoginHistory.created_at.desc())
            .offset((page - 1) * limit)
            .limit(limit)
        )
    ).scalars().all()
    return {
        "data": [
            {
                "id": str(r.id),
                "provider": r.provider,
                "ip": r.ip,
                "user_agent": r.user_agent,
                "status": r.status,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
        "pagination": _pagination_meta(page, limit, int(total)),
    }

async def get_login_history_controller(
    token: str, page: int = 1, limit: int = HISTORY_DEFAULT_LIMIT
):
    uid, err = _resolve_uid_or_error(token)
    if err:
        return err
    page, limit = _normalize_page_params(page, limit)

    async with SessionLocal() as session:
        suffix = build_suffix(uid=str(uid), page=page, limit=limit)
        result = await cached_async(
            LOGIN_HISTORY_CACHE_NAMESPACE,
            LOGIN_HISTORY_CACHE_TTL_SECONDS,
            lambda: _fetch_login_history(session, uid, page, limit),
            suffix=suffix,
        )
        return _history_response("ดึงประวัติการเข้าสู่ระบบสำเร็จ", result)

async def _fetch_password_history(session, uid, page: int, limit: int):
    conditions = (
        AuditLog.actor_uid == uid,
        AuditLog.action == PASSWORD_CHANGE_AUDIT_ACTION,
    )
    total = (
        await session.execute(
            select(func.count()).select_from(AuditLog).where(*conditions)
        )
    ).scalar_one()
    rows = (
        await session.execute(
            select(AuditLog)
            .where(*conditions)
            .order_by(AuditLog.created_at.desc())
            .offset((page - 1) * limit)
            .limit(limit)
        )
    ).scalars().all()

    history = []
    for row in rows:
        detail: dict = {}
        if row.detail:
            try:
                parsed = json.loads(row.detail)
                if isinstance(parsed, dict):
                    detail = parsed
            except (TypeError, ValueError):
                detail = {}
        history.append(
            {
                "id": str(row.log_id),
                "ip": detail.get("ip"),
                "user_agent": detail.get("user_agent"),
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
        )
    return {"data": history, "pagination": _pagination_meta(page, limit, int(total))}

async def get_password_history_controller(
    token: str, page: int = 1, limit: int = HISTORY_DEFAULT_LIMIT
):
    uid, err = _resolve_uid_or_error(token)
    if err:
        return err
    page, limit = _normalize_page_params(page, limit)

    async with SessionLocal() as session:
        suffix = build_suffix(uid=str(uid), page=page, limit=limit)
        result = await cached_async(
            PASSWORD_HISTORY_CACHE_NAMESPACE,
            PASSWORD_HISTORY_CACHE_TTL_SECONDS,
            lambda: _fetch_password_history(session, uid, page, limit),
            suffix=suffix,
        )
        return _history_response("ดึงประวัติการเปลี่ยนรหัสผ่านสำเร็จ", result)

_EMAIL_CHANGE_LIMIT = 5
_EMAIL_CHANGE_WINDOW_SECONDS = 60 * 10

async def change_email_controller(token: str, email: str):
    uid, err = _resolve_uid_or_error(token)
    if err:
        return err

    async with SessionLocal() as session:
        user = await get_user_or_404(session, uid)
        try:
            ensure_not_banned(user)
        except AuthError as exc:
            return error(exc.code, exc.message)

    if is_rate_limited("profile:email", str(uid), _EMAIL_CHANGE_LIMIT, _EMAIL_CHANGE_WINDOW_SECONDS):
        return error(AuthStatus.RATE_LIMITED, "คุณขอเปลี่ยนอีเมลบ่อยเกินไป กรุณาลองใหม่ภายหลัง")

    async with SessionLocal() as session:
        user = await get_user_or_404(session, uid)
        try:
            return await start_email_change(session, user, email)
        except AuthError as exc:
            return error(exc.code, exc.message)

async def verify_old_email_controller(token: str, otp_token: str, otp: str):
    uid, err = _resolve_uid_or_error(token)
    if err:
        return err

    async with SessionLocal() as session:
        user = await get_user_or_404(session, uid)
        try:
            ensure_not_banned(user)
        except AuthError as exc:
            return error(exc.code, exc.message)

        try:
            return await verify_old_email_otp(session, user, otp_token, otp)
        except AuthError as exc:
            return error(exc.code, exc.message)

async def resend_email_otp_controller(token: str):
    uid, err = _resolve_uid_or_error(token)
    if err:
        return err

    async with SessionLocal() as session:
        user = await get_user_or_404(session, uid)
        try:
            ensure_not_banned(user)
        except AuthError as exc:
            return error(exc.code, exc.message)

    if is_rate_limited("profile:email-otp", str(uid), _EMAIL_CHANGE_LIMIT, _EMAIL_CHANGE_WINDOW_SECONDS):
        return error(AuthStatus.RATE_LIMITED, "คุณขอรหัส OTP บ่อยเกินไป กรุณาลองใหม่ภายหลัง")

    async with SessionLocal() as session:
        user = await get_user_or_404(session, uid)
        try:
            return await resend_email_otp(session, user)
        except AuthError as exc:
            return error(exc.code, exc.message)

async def confirm_email_controller(token: str, otp_token: str, otp: str):
    uid, err = _resolve_uid_or_error(token)
    if err:
        return err

    async with SessionLocal() as session:
        user = await get_user_or_404(session, uid)
        try:
            ensure_not_banned(user)
        except AuthError as exc:
            return error(exc.code, exc.message)

        try:
            result = await confirm_email_change(session, user, otp_token, otp)
        except AuthError as exc:
            return error(exc.code, exc.message)

    if result.get("success"):
        invalidate_cached(PROFILE_CACHE_NAMESPACE)
    return result

_PASSWORD_CHANGE_LIMIT = 5
_PASSWORD_CHANGE_WINDOW_SECONDS = 60 * 10

async def change_password_controller(
    token: str,
    current_password: str,
    new_password: str,
    user_agent: str | None = None,
    ip: str | None = None,
):
    uid, err = _resolve_uid_or_error(token)
    if err:
        return err

    async with SessionLocal() as session:
        user = await get_user_or_404(session, uid)
        try:
            ensure_not_banned(user)
        except AuthError as exc:
            return error(exc.code, exc.message)

    if is_rate_limited(
        "profile:password", str(uid), _PASSWORD_CHANGE_LIMIT, _PASSWORD_CHANGE_WINDOW_SECONDS
    ):
        return error(AuthStatus.RATE_LIMITED, "คุณเปลี่ยนรหัสผ่านบ่อยเกินไป กรุณาลองใหม่ภายหลัง")

    async with SessionLocal() as session:
        try:
            await change_password(session, uid, current_password, new_password)
        except HTTPException as exc:
            return error(_password_error_status(exc.status_code), exc.detail)

        await write_audit_log(
            session,
            actor_uid=uid,
            target_uid=uid,
            action=PASSWORD_CHANGE_AUDIT_ACTION,
            detail=json.dumps({"ip": ip, "user_agent": user_agent}, ensure_ascii=False),
        )
        await session.commit()

    invalidate_cached(PASSWORD_HISTORY_CACHE_NAMESPACE)
    return success(AuthStatus.PASSWORD_CHANGE_SUCCESS, "เปลี่ยนรหัสผ่านสำเร็จ", None)

def _password_error_status(status_code: int) -> str:
    if status_code == 401:
        return AuthStatus.CURRENT_PASSWORD_INVALID
    if status_code == 409:
        return AuthStatus.NO_LOCAL_PASSWORD
    if status_code == 400:
        return AuthStatus.PASSWORD_UNCHANGED
    return AuthStatus.PASSWORD_POLICY_INVALID

async def get_notification_counts_controller(token: str, reports_since=None, public_since=None):
    uid, err = _resolve_uid_or_error(token)
    if err:
        return err

    async with SessionLocal() as session:
        data = await unread_notification_counts(session, uid, reports_since, public_since)
        return success(AuthStatus.LOGIN_SUCCESS, "ดึงจำนวนรายการใหม่สำเร็จ", data)

_AVATAR_UPLOAD_LIMIT = 10
_AVATAR_UPLOAD_WINDOW_SECONDS = 60 * 10
_USERNAME_UPDATE_LIMIT = 10
_USERNAME_UPDATE_WINDOW_SECONDS = 60 * 10

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
    if not _AVATAR_FILENAME_RE.match(file_name):
        raise HTTPException(status_code=404, detail="Avatar not found")

    safe_path = (AVATAR_DIR / file_name).resolve()
    if safe_path.parent != AVATAR_DIR.resolve() or not safe_path.is_file():
        raise HTTPException(status_code=404, detail="Avatar not found")

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
