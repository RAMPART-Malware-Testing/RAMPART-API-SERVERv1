import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cores.Schema.schema_class import User
from cores.redis import redis_client
from services.admin.admin_service import write_audit_log
from services.oauth.oauth_service import user_public_dict
from services.otp_service import OTPService
from services.token_service import TokenService
from utils.email_normalize import normalize_email, normalized_email_expr
from utils.jwt import create_token
from utils.response import error, success
from utils.status_code import AuthStatus

CHANGE_EMAIL_OTP_ACTION = "change-email"
OLD_EMAIL_OTP_ACTION = "change-email-old"
CHANGE_EMAIL_TOKEN_TYPE = "change-email"
CHANGE_EMAIL_TOKEN_MINUTES = 10
PENDING_EMAIL_KEY = "profile:pending_email"
PENDING_EMAIL_TTL_SECONDS = 15 * 60
EMAIL_OLD_TOKEN_MINUTES = 10

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[A-Za-z]{2,}$")


def _pending_email_key(uid) -> str:
    return f"{PENDING_EMAIL_KEY}:{uid}"


async def _email_taken_by_other(session: AsyncSession, uid, candidate: str) -> bool:
    taken = await session.execute(
        select(User.uid).where(
            normalized_email_expr(User.email) == candidate,
            User.uid != uid,
        )
    )
    return taken.scalar_one_or_none() is not None


async def start_email_change(session: AsyncSession, actor: User, email: str) -> dict:
    candidate = normalize_email(email.strip())
    if not EMAIL_RE.match(candidate):
        return error(AuthStatus.INVALID_CREDENTIALS, "รูปแบบอีเมลไม่ถูกต้อง")

    if candidate == normalize_email(actor.email or ""):
        return error(AuthStatus.EMAIL_UNCHANGED, "อีเมลนี้เป็นอีเมลปัจจุบันอยู่แล้ว")

    if await _email_taken_by_other(session, actor.uid, candidate):
        return error(AuthStatus.EMAIL_TAKEN, "อีเมลนี้ถูกใช้งานในระบบแล้ว")

    if not actor.email or not EMAIL_RE.match(actor.email):
        return error(AuthStatus.INVALID_CREDENTIALS, "บัญชีนี้ยังไม่มีอีเมลเดิมที่ใช้งานได้")

    if redis_client is not None:
        try:
            redis_client.setex(_pending_email_key(actor.uid), PENDING_EMAIL_TTL_SECONDS, candidate)
        except Exception as exc:
            print(f"[ChangeEmail] unable to store pending email: {exc}")

    otp_token = create_token(
        subject=str(actor.uid),
        token_type=CHANGE_EMAIL_TOKEN_TYPE,
        expires_minutes=EMAIL_OLD_TOKEN_MINUTES,
    )
    otp_response = await OTPService.create_otp_session(
        action=OLD_EMAIL_OTP_ACTION,
        identifier=str(actor.uid),
        token=otp_token,
        email=actor.email,
    )
    if not otp_response.get("success"):
        return otp_response
    return success(
        AuthStatus.OTP_SENT,
        otp_response.get("message") or f"ส่งรหัส OTP ไปยังอีเมลเดิม ({actor.email}) แล้ว",
        {
            "token": otp_token,
            "old_email": actor.email,
            "new_email": candidate,
            "expires_in": otp_response.get("data", {}).get("expires_in"),
            "email_sent": otp_response.get("data", {}).get("email_sent", True),
        },
    )


async def verify_old_email_otp(session: AsyncSession, actor: User, token: str, otp: str) -> dict:
    payload, err = TokenService.verify_token(token, CHANGE_EMAIL_TOKEN_TYPE)
    if err:
        return error(AuthStatus.OTP_EXPIRED, "รหัส OTP หมดอายุแล้ว กรุณาขอรหัสใหม่")

    outcome, remaining = OTPService.verify_otp(
        OLD_EMAIL_OTP_ACTION, token, otp, identifier=payload.get("sub")
    )
    if outcome != "ok":
        if outcome == "wrong":
            return error(AuthStatus.OTP_WRONG, "รหัส OTP ไม่ถูกต้อง", {"attempts_remaining": remaining})
        if outcome == "locked":
            return error(AuthStatus.OTP_LOCKED, "กรอกรหัส OTP ผิดหลายครั้งเกินไป กรุณาขอรหัสใหม่ภายหลัง")
        return error(AuthStatus.OTP_EXPIRED, "รหัส OTP หมดอายุแล้ว กรุณาขอรหัสใหม่")

    OTPService.clear_otp_session(OLD_EMAIL_OTP_ACTION, token, str(actor.uid))
    return await resend_email_otp(session, actor, action=CHANGE_EMAIL_OTP_ACTION)


async def resend_email_otp(session: AsyncSession, actor: User, action: str = CHANGE_EMAIL_OTP_ACTION) -> dict:
    pending_email = None
    if redis_client is not None:
        try:
            pending_email = redis_client.get(_pending_email_key(actor.uid))
        except Exception as exc:
            print(f"[ChangeEmail] unable to read pending email: {exc}")
    if not pending_email:
        return error(
            AuthStatus.TOKEN_EXPIRED,
            "ไม่พบรายการเปลี่ยนอีเมลที่ค้างอยู่ กรุณาเริ่มเปลี่ยนอีเมลใหม่จากหน้าโปรไฟล์",
        )
    if isinstance(pending_email, bytes):
        pending_email = pending_email.decode("utf-8")

    if await _email_taken_by_other(session, actor.uid, pending_email):
        return error(AuthStatus.EMAIL_TAKEN, "อีเมลนี้ถูกใช้งานในระบบแล้ว")

    otp_token = create_token(
        subject=str(actor.uid),
        token_type=CHANGE_EMAIL_TOKEN_TYPE,
        expires_minutes=CHANGE_EMAIL_TOKEN_MINUTES,
    )
    otp_response = await OTPService.create_otp_session(
        action=action,
        identifier=str(actor.uid),
        token=otp_token,
        email=pending_email,
    )
    if not otp_response.get("success"):
        return otp_response
    return success(
        AuthStatus.OTP_SENT,
        otp_response.get("message") or f"ส่งรหัส OTP ไปยัง {pending_email} แล้ว",
        {
            "token": otp_token,
            "email": pending_email,
            "expires_in": otp_response.get("data", {}).get("expires_in"),
            "email_sent": otp_response.get("data", {}).get("email_sent", True),
        },
    )

async def confirm_email_change(session: AsyncSession, actor: User, token: str, otp: str) -> dict:
    payload, err = TokenService.verify_token(token, CHANGE_EMAIL_TOKEN_TYPE)
    if err:
        return err
    if str(payload.get("sub")) != str(actor.uid):
        return error(AuthStatus.TOKEN_INVALID, "โทเค็นนี้ไม่ใช่ของบัญชีที่กำลังเปลี่ยนอีเมล")

    outcome, remaining = OTPService.verify_otp(
        CHANGE_EMAIL_OTP_ACTION, token, otp, identifier=payload.get("sub")
    )
    if outcome != "ok":
        if outcome == "wrong":
            return error(AuthStatus.OTP_WRONG, "รหัส OTP ไม่ถูกต้อง", {"attempts_remaining": remaining})
        if outcome == "locked":
            return error(AuthStatus.OTP_LOCKED, "กรอกรหัส OTP ผิดหลายครั้งเกินไป กรุณาขอรหัสใหม่ภายหลัง")
        return error(AuthStatus.OTP_EXPIRED, "รหัส OTP หมดอายุแล้ว กรุณาขอรหัสใหม่")

    pending_email = None
    if redis_client is not None:
        try:
            pending_email = redis_client.get(_pending_email_key(actor.uid))
        except Exception as exc:
            print(f"[ChangeEmail] unable to read pending email: {exc}")
    if not pending_email:
        return error(AuthStatus.TOKEN_EXPIRED, "หมดเวลายืนยันอีเมล กรุณาเริ่มเปลี่ยนอีเมลใหม่")
    if isinstance(pending_email, bytes):
        pending_email = pending_email.decode("utf-8")

    if await _email_taken_by_other(session, actor.uid, pending_email):
        return error(AuthStatus.EMAIL_TAKEN, "อีเมลนี้ถูกใช้งานในระบบแล้ว")

    target = await session.get(User, actor.uid)
    if target is None:
        return error(AuthStatus.USER_NOT_FOUND, "ไม่พบบัญชีผู้ใช้")

    previous_email = target.email
    target.email = pending_email

    await write_audit_log(
        session,
        actor_uid=target.uid,
        target_uid=target.uid,
        action="change_email",
        detail=f"{previous_email}->{pending_email}",
    )
    await session.commit()
    await session.refresh(target)

    OTPService.clear_otp_session(CHANGE_EMAIL_OTP_ACTION, token, str(target.uid))
    if redis_client is not None:
        try:
            redis_client.delete(_pending_email_key(target.uid))
        except Exception:
            pass

    return success(AuthStatus.PROFILE_UPDATE_SUCCESS, "เปลี่ยนอีเมลสำเร็จ", user_public_dict(target))
