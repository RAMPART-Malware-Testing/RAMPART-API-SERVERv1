import re

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from cores.Schema.schema_class import AuditLog, User
from cores.async_pg_db import SessionLocal
from services.master_config import record_master_identity
from services.oauth.oauth_service import user_public_dict
from utils.cypto.PasswordCreateAndVerify import get_password_hash
from utils.email_normalize import EMAIL_PATTERN, normalize_email, normalized_email_expr
from utils.jwt import create_token
from utils.password_policy import validate_password_policy
from utils.rate_limit import is_rate_limited
from utils.response import error, success
from utils.status_code import AuthStatus

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{3,50}$")
USERNAME_MAX_LENGTH = 50
EMAIL_MAX_LENGTH = 255

_SETUP_ADVISORY_LOCK_KEY = 6010720240713

_ATTEMPT_LIMIT = 10
_ATTEMPT_WINDOW_SECONDS = 10 * 60

ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7


async def get_setup_status() -> dict:
    async with SessionLocal() as session:
        total = await session.execute(select(func.count()).select_from(User))
        user_count = total.scalar_one()

    return success(
        AuthStatus.FIRST_RUN_SUCCESS,
        "ตรวจสอบสถานะการตั้งค่าครั้งแรกสำเร็จ",
        {"needs_setup": user_count == 0},
    )


async def _users_table_is_empty(session: AsyncSession) -> bool:
    total = await session.execute(select(func.count()).select_from(User))
    return total.scalar_one() == 0


def _validate(body) -> dict | None:
    username = (body.username or "").strip()
    raw_email = (body.email or "").strip()
    password = body.password or ""
    confirm_password = body.confirmPassword or ""

    if not USERNAME_PATTERN.match(username):
        return error(
            AuthStatus.SETUP_INVALID_INPUT,
            "ชื่อผู้ใช้ต้องมี 3-50 ตัวอักษร และใช้ได้เฉพาะตัวอักษรอังกฤษ ตัวเลข จุด ขีดกลาง และขีดล่าง",
        )
    if len(username) > USERNAME_MAX_LENGTH:
        return error(AuthStatus.SETUP_INVALID_INPUT, "ชื่อผู้ใช้ยาวเกินไป")

    normalized = normalize_email(raw_email)
    if not EMAIL_PATTERN.match(normalized):
        return error(AuthStatus.SETUP_INVALID_INPUT, "รูปแบบอีเมลไม่ถูกต้อง")
    if len(normalized) > EMAIL_MAX_LENGTH:
        return error(AuthStatus.SETUP_INVALID_INPUT, "อีเมลยาวเกินไป")

    if password != confirm_password:
        return error(AuthStatus.SETUP_INVALID_INPUT, "รหัสผ่านและยืนยันรหัสผ่านไม่ตรงกัน")

    policy_error = validate_password_policy(password)
    if policy_error:
        return error(AuthStatus.PASSWORD_POLICY_INVALID, policy_error)

    return None


async def complete_first_run_setup(body, client_ip: str) -> dict:
    ip = client_ip or "unknown"

    if is_rate_limited("first-run-setup", ip, _ATTEMPT_LIMIT, _ATTEMPT_WINDOW_SECONDS):
        return error(
            AuthStatus.SETUP_RATE_LIMITED,
            "พยายามตั้งค่าหลายครั้งเกินไป กรุณารอสักครู่แล้วลองใหม่",
        )

    validation_error = _validate(body)
    if validation_error:
        return validation_error

    username = body.username.strip()
    email = normalize_email(body.email.strip())

    try:
        session = SessionLocal()
        try:
            await session.execute(
                text("SELECT pg_advisory_xact_lock(:key)"),
                {"key": _SETUP_ADVISORY_LOCK_KEY},
            )

            if not await _users_table_is_empty(session):
                await session.rollback()
                return error(
                    AuthStatus.SETUP_ALREADY_COMPLETED,
                    "ระบบมีผู้ใช้งานแล้ว ไม่สามารถตั้งค่าครั้งแรกซ้ำได้",
                )

            taken_username = await session.execute(
                select(User.uid).where(User.username == username).limit(1)
            )
            if taken_username.scalar_one_or_none() is not None:
                await session.rollback()
                return error(AuthStatus.USERNAME_TAKEN, "ชื่อผู้ใช้นี้ถูกใช้งานแล้ว")

            taken_email = await session.execute(
                select(User.uid)
                .where(normalized_email_expr(User.email) == email)
                .limit(1)
            )
            if taken_email.scalar_one_or_none() is not None:
                await session.rollback()
                return error(AuthStatus.EMAIL_TAKEN, "อีเมลนี้ถูกใช้งานแล้ว")

            user = User(
                username=username,
                email=email,
                password=get_password_hash(body.password),
                avatar_url=None,
                role="master",
                status="active",
                is_banned=False,
            )
            session.add(user)
            await session.flush()
            master_uid = user.uid

            session.add(
                AuditLog(
                    actor_uid=user.uid,
                    target_uid=user.uid,
                    action="first_run_setup",
                    detail=f"ip={ip}",
                )
            )
            await session.commit()
            await session.refresh(user)
            master_payload = user_public_dict(user)
        finally:
            await session.close()
    except IntegrityError as exc:
        print(f"[FirstRunSetup] IntegrityError during first-run setup: {exc}")
        return error(
            AuthStatus.SETUP_ALREADY_COMPLETED,
            "ระบบมีผู้ใช้งานแล้ว ไม่สามารถตั้งค่าครั้งแรกซ้ำได้",
        )

    try:
        record_master_identity(master_uid, email)
    except OSError as exc:
        print(f"[FirstRunSetup] unable to record master config: {exc}")

    access_token = create_token(
        subject=str(master_uid),
        token_type="access",
        expires_minutes=ACCESS_TOKEN_EXPIRE_MINUTES,
    )

    print(f"[FirstRunSetup] Created first master account: {email} (from {ip})")
    return success(
        AuthStatus.FIRST_RUN_SUCCESS,
        "ตั้งค่าบัญชีผู้ดูแลระบบครั้งแรกสำเร็จ",
        {
            "username": master_payload.get("username"),
            "access_token": access_token,
            "data": master_payload,
        },
    )