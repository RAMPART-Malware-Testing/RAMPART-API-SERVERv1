import re
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cores.Schema.schema_class import User
from cores.redis import redis_client
from services.admin.authz import AuthError, ROLE_MASTER
from services.admin.admin_service import write_audit_log
from services.otp_service import OTPService
from services.token_service import TokenService
from utils.cypto.PasswordCreateAndVerify import get_password_hash, verify_password
from utils.email_normalize import normalize_email, normalized_email_expr
from utils.password_policy import validate_password_policy
from utils.response import error, success
from utils.status_code import AuthStatus

SETUP_OTP_ACTION = "master-setup"
SETUP_TOKEN_TYPE = "master-setup"
SETUP_TOKEN_MINUTES = 10
PENDING_EMAIL_KEY = "master_setup:pending_email"
PENDING_EMAIL_TTL_SECONDS = 15 * 60

GMAIL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._%+-]*[a-z0-9])?@gmail\.com$")


def _pending_email_key(uid) -> str:
    return f"{PENDING_EMAIL_KEY}:{uid}"


async def start_master_setup(session: AsyncSession, actor: User, email: str) -> dict:
    if actor.role != ROLE_MASTER:
        raise AuthError(403, "INSUFFICIENT_ROLE", "เฉพาะ master เท่านั้นที่ตั้งค่าบัญชีนี้ได้")

    candidate = normalize_email(email.strip())
    if not GMAIL_RE.match(candidate):
        return error(AuthStatus.INVALID_CREDENTIALS, "กรุณาระบุอีเมล Gmail (@gmail.com) เท่านั้น")

    taken = await session.execute(
        select(User.uid).where(
            normalized_email_expr(User.email) == candidate,
            User.uid != actor.uid,
        )
    )
    if taken.scalar_one_or_none() is not None:
        return error(AuthStatus.USERNAME_TAKEN, "อีเมลนี้ถูกใช้งานแล้ว")

    if redis_client is not None:
        try:
            redis_client.setex(_pending_email_key(actor.uid), PENDING_EMAIL_TTL_SECONDS, candidate)
        except Exception as exc:
            print(f"[MasterSetup] unable to store pending email: {exc}")

    from utils.jwt import create_token

    token = create_token(
        subject=str(actor.uid),
        token_type=SETUP_TOKEN_TYPE,
        expires_minutes=SETUP_TOKEN_MINUTES,
    )
    otp_response = await OTPService.create_otp_session(
        action=SETUP_OTP_ACTION,
        identifier=str(actor.uid),
        token=token,
        email=candidate,
    )
    if not otp_response.get("success"):
        return otp_response
    return success(
        AuthStatus.OTP_SENT,
        otp_response.get("message") or f"ส่งรหัส OTP ไปยัง {candidate} แล้ว",
        {
            "token": token,
            "email": candidate,
            "expires_in": otp_response.get("data", {}).get("expires_in"),
            "email_sent": otp_response.get("data", {}).get("email_sent", True),
        },
    )


async def confirm_master_setup(
    session: AsyncSession,
    actor: User,
    token: str | None,
    otp: str | None,
    new_password: str,
    skip_otp: bool = False,
) -> dict:
    if actor.role != ROLE_MASTER:
        raise AuthError(403, "INSUFFICIENT_ROLE", "เฉพาะ master เท่านั้นที่ตั้งค่าบัญชีนี้ได้")
    if not actor.must_setup:
        return error(AuthStatus.INSUFFICIENT_ROLE, "บัญชีนี้ตั้งค่าเรียบร้อยแล้ว")

    policy_error = validate_password_policy(new_password)
    if policy_error:
        return error(AuthStatus.PASSWORD_POLICY_INVALID, policy_error)

    if verify_password(actor.password or "", new_password):
        return error(AuthStatus.PASSWORD_UNCHANGED, "รหัสผ่านใหม่ต้องไม่ซ้ำกับรหัสผ่านเดิม")

    pending_email = None
    if skip_otp:
        audit_detail = "password-only (email/otp skipped)"
    else:
        if not token or not otp:
            return error(AuthStatus.OTP_EXPIRED, "กรุณากรอกรหัส OTP หรือเลือกข้ามขั้นตอนยืนยันอีเมล")

        payload, err = TokenService.verify_token(token, SETUP_TOKEN_TYPE)
        if err:
            return err
        if str(payload.get("sub")) != str(actor.uid):
            return error(AuthStatus.TOKEN_INVALID, "โทเค็นนี้ไม่ใช่ของบัญชีที่กำลังตั้งค่า")

        outcome, remaining = OTPService.verify_otp(
            SETUP_OTP_ACTION, token, otp, identifier=payload.get("sub")
        )
        if outcome != "ok":
            if outcome == "wrong":
                return error(
                    AuthStatus.OTP_WRONG,
                    "รหัส OTP ไม่ถูกต้อง",
                    {"attempts_remaining": remaining},
                )
            if outcome == "locked":
                return error(AuthStatus.OTP_LOCKED, "กรอกรหัส OTP ผิดหลายครั้งเกินไป กรุณาขอรหัสใหม่ภายหลัง")
            return error(AuthStatus.OTP_EXPIRED, "รหัส OTP หมดอายุแล้ว กรุณาขอรหัสใหม่")

        if redis_client is not None:
            try:
                pending_email = redis_client.get(_pending_email_key(actor.uid))
            except Exception as exc:
                print(f"[MasterSetup] unable to read pending email: {exc}")
        if not pending_email:
            return error(AuthStatus.TOKEN_EXPIRED, "หมดเวลายืนยันอีเมล กรุณาเริ่มตั้งค่าใหม่")
        if isinstance(pending_email, bytes):
            pending_email = pending_email.decode("utf-8")
        audit_detail = f"email={pending_email}"

    target = await session.get(User, actor.uid)
    if target is None:
        raise AuthError(401, "USER_NOT_FOUND", "ไม่พบบัญชีผู้ใช้")

    if pending_email:
        target.email = pending_email
    target.password = get_password_hash(new_password)
    target.must_setup = False

    await write_audit_log(
        session,
        actor_uid=target.uid,
        target_uid=target.uid,
        action="master_setup",
        detail=audit_detail,
    )
    await session.commit()
    await session.refresh(target)

    if token:
        OTPService.clear_otp_session(SETUP_OTP_ACTION, token, str(target.uid))
    if redis_client is not None:
        try:
            redis_client.delete(_pending_email_key(target.uid))
        except Exception:
            pass

    return success(AuthStatus.PASSWORD_CHANGE_SUCCESS, "ตั้งค่าบัญชี master สำเร็จ", None)
