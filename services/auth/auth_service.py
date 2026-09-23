from schemas.auth import RegisterConfirmParame, RegisterParame, ResetPasswdParame
from services.token_service import TokenService
from utils.jwt import decode_token, get_token_type, get_token_subject
from utils.response import error, success
from utils.status_code import AuthStatus

def verify_access_token(token: str) -> str:
    payload = decode_token(token)

    if get_token_type(payload) != "access":
        raise ValueError("ประเภทโทเค็นไม่ถูกต้อง")

    uid = get_token_subject(payload)
    if not uid:
        raise ValueError("ข้อมูลเพย์โหลดของโทเค็นไม่ถูกต้อง")

    return uid

from sqlalchemy import select
from cores.async_pg_db import SessionLocal
from cores.Schema.schema_class import LoginHistory, OAuthAccount, User
from utils.cypto.PasswordCreateAndVerify import get_password_hash, verify_password
from utils.email_normalize import normalize_email, normalized_email_expr
from utils.jwt import create_token
from utils.rate_limit import is_rate_limited
from services.otp_service import OTPService, MAX_OTP_ATTEMPTS

import hashlib
import json
import time

try:
    from cores.redis import redis_client
except Exception:
    redis_client = None

DEVICE_TOKEN_TTL_MINUTES = 60 * 24 * 7

# --- auth throttles / brute-force protection --------------------------------
# Per-IP fixed windows (utils.rate_limit, fails OPEN without Redis) plus a
# per-email wrong-password lockout below. Availability over strictness,
# matching the codebase's Redis posture.
LOGIN_IP_RATE_LIMIT = 20
LOGIN_IP_RATE_WINDOW_SECONDS = 15 * 60
AUTH_IP_RATE_LIMIT = 15
AUTH_IP_RATE_WINDOW_SECONDS = 15 * 60
OTP_SEND_EMAIL_LIMIT = 5
OTP_SEND_EMAIL_WINDOW_SECONDS = 60 * 60
PWFAIL_LIMIT = 10
PWFAIL_WINDOW_SECONDS = 15 * 60
REGISTER_DATA_TTL_SECONDS = 300  # matches the "register" JWT TTL (5 min)
REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7

def _ip_rate_limited(bucket: str, ip) -> bool:
    return is_rate_limited(bucket, str(ip or "unknown"), AUTH_IP_RATE_LIMIT, AUTH_IP_RATE_WINDOW_SECONDS)

def _pwfail_key(normalized_email: str) -> str:
    return f"ratelimit:auth:pwfail:{normalized_email}"

def _pwfail_lockout_remaining(normalized_email: str) -> int | None:
    """Seconds left of the wrong-password lockout for this email, or None."""
    if redis_client is None:
        return None
    try:
        key = _pwfail_key(normalized_email)
        current = redis_client.get(key)
        if current is not None and int(current) >= PWFAIL_LIMIT:
            ttl = redis_client.ttl(key)
            return ttl if isinstance(ttl, int) and ttl > 0 else PWFAIL_WINDOW_SECONDS
    except Exception:
        pass  # fail open - never block logins because Redis is down
    return None

def _record_pwfail(normalized_email: str) -> None:
    if redis_client is None:
        return
    try:
        key = _pwfail_key(normalized_email)
        count = redis_client.incr(key)
        if count == 1:
            redis_client.expire(key, PWFAIL_WINDOW_SECONDS)
    except Exception as exc:
        print(f"[auth] pwfail counter error for {normalized_email}: {exc}")

def _reset_pwfail(normalized_email: str) -> None:
    if redis_client is None:
        return
    try:
        redis_client.delete(_pwfail_key(normalized_email))
    except Exception:
        pass

def _get_register_data(token: str) -> dict | None:
    """Registration credentials staged in Redis by register(). Fails CLOSED:
    without the staged data the registration cannot complete (the password
    no longer travels inside the JWT payload)."""
    if redis_client is None:
        return None
    try:
        raw = redis_client.get(f"register_data:{token}")
    except Exception as exc:
        print(f"[auth] register data read error: {exc}")
        return None
    if not raw:
        return None
    try:
        if isinstance(raw, bytes):
            raw = raw.decode()
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) and data.get("password") else None

def _refresh_used_key(refresh_token: str) -> str:
    return f"refresh_used:{hashlib.sha256(refresh_token.encode()).hexdigest()}"

def _is_refresh_token_used(refresh_token: str) -> bool:
    """True if this exact refresh token was already exchanged (rotation).
    Fails OPEN when Redis is unreachable - never crash the refresh flow."""
    if redis_client is None:
        return False
    try:
        return bool(redis_client.exists(_refresh_used_key(refresh_token)))
    except Exception:
        return False

def _blacklist_refresh_token(refresh_token: str, payload) -> None:
    """Mark a consumed refresh token for the rest of its lifetime so it can
    never be replayed. Best-effort: a Redis outage must not stop the new
    token pair from being issued."""
    if redis_client is None:
        return
    try:
        exp = (payload or {}).get("exp")
        remaining = int(exp - time.time()) if isinstance(exp, (int, float)) else REFRESH_TOKEN_TTL_SECONDS
        if remaining <= 0:
            remaining = REFRESH_TOKEN_TTL_SECONDS
        redis_client.setex(_refresh_used_key(refresh_token), remaining, "1")
    except Exception as exc:
        print(f"[auth] refresh blacklist error: {exc}")

def _issue_device_token(uid, email: str) -> str:
    """A device token is bound to BOTH the account uid and its email at
    issuance time (see login_confirm/oauth_callback_controller - both are
    the only two places that mint one). login()'s bypass check requires
    both to match the account being logged into, so a device token minted
    for a@a.com can never skip OTP for a login attempt as b@b.com, and a
    device token can never be reused for any account other than the one
    it was issued for even if somehow forged with a different email in
    isolation - `sub` (uid) is checked independently, not derived from the
    email claim."""
    return create_token(
        subject=str(uid),
        token_type="device",
        expires_minutes=DEVICE_TOKEN_TTL_MINUTES,
        extra_payload={"email": email},
    )

async def _record_login_history(session, *, uid, provider: str, ip, user_agent, status: str) -> None:
    """Best-effort audit trail row. Never raises - a logging failure must
    never block an otherwise-successful login."""
    try:
        session.add(
            LoginHistory(
                uid=uid,
                provider=provider,
                ip=ip,
                user_agent=user_agent,
                status=status,
            )
        )
    except Exception as exc:  # pragma: no cover - defensive
        print(f"[login_history] failed to queue row for {uid}: {exc}")

def _otp_error_response(outcome: str, detail: int | None):
    if outcome == "wrong":
        return error(
            AuthStatus.OTP_WRONG,
            f"รหัส OTP ไม่ถูกต้อง เหลืออีก {detail} ครั้งก่อนถูกระงับชั่วคราว"
            if detail and detail > 0
            else "รหัส OTP ไม่ถูกต้อง คุณกรอกผิดครบจำนวนครั้งที่กำหนดแล้ว",
            {"attempts_remaining": detail},
        )
    if outcome == "locked":
        return error(
            AuthStatus.OTP_LOCKED,
            f"คุณกรอกรหัส OTP ผิดครบ {MAX_OTP_ATTEMPTS} ครั้งแล้ว "
            + (f"กรุณารออีก {detail} วินาทีแล้วลองใหม่" if detail else "กรุณาขอรหัส OTP ใหม่อีกครั้ง"),
            {"locked_seconds_remaining": detail},
        )
    return error(
        AuthStatus.OTP_EXPIRED,
        "รหัส OTP หมดอายุหรือไม่ถูกต้อง กรุณาเริ่มดำเนินการใหม่อีกครั้ง",
    )

class AuthService:

    @staticmethod
    async def login(body, user_agent, ip, deviceToken):
        normalized_email = normalize_email(body.email)

        if is_rate_limited("auth:login", str(ip or "unknown"), LOGIN_IP_RATE_LIMIT, LOGIN_IP_RATE_WINDOW_SECONDS):
            return error(AuthStatus.RATE_LIMITED, "คุณพยายามเข้าสู่ระบบบ่อยเกินไป กรุณาลองอีกครั้งภายหลัง")

        lockout_seconds = _pwfail_lockout_remaining(normalized_email)
        if lockout_seconds is not None:
            return error(
                AuthStatus.RATE_LIMITED,
                f"คุณกรอกรหัสผ่านผิดหลายครั้งเกินไป กรุณาลองอีกครั้งภายหลัง (ประมาณ {lockout_seconds} วินาที)",
                {"locked_seconds_remaining": lockout_seconds},
            )

        async with SessionLocal() as session:
            result = await session.execute(
                select(User).where(normalized_email_expr(User.email) == normalized_email)
            )
            user = result.scalar_one_or_none()

            if not user:
                _record_pwfail(normalized_email)
                return error(AuthStatus.INVALID_CREDENTIALS, "ข้อมูลการเข้าสู่ระบบไม่ถูกต้อง")

            if not user.password or not verify_password(user.password, body.password):
                _record_pwfail(normalized_email)
                return error(AuthStatus.INVALID_CREDENTIALS, "ข้อมูลการเข้าสู่ระบบไม่ถูกต้อง")

            _reset_pwfail(normalized_email)

            oauth_link = await session.execute(
                select(OAuthAccount.id).where(OAuthAccount.uid == user.uid).limit(1)
            )
            has_linked_oauth = oauth_link.scalar_one_or_none() is not None

            if deviceToken and not has_linked_oauth:
                payload, err = TokenService.verify_token(deviceToken, "device")
                if not err and payload.get("sub") == str(user.uid) and payload.get("email") == user.email:
                    access_token = create_token(
                        subject=str(user.uid),
                        token_type="access",
                        expires_minutes=60 * 24 * 7
                    )
                    refreshed_device_token = _issue_device_token(user.uid, user.email)

                    await _record_login_history(
                        session, uid=user.uid, provider="password", ip=ip,
                        user_agent=user_agent, status="success_device_bypass",
                    )
                    await session.commit()

                    user_dict = user.__dict__.copy()
                    user_dict.pop("password", None)
                    user_dict.pop("_sa_instance_state", None)
                    return success(
                        AuthStatus.LOGIN_SUCCESS,
                        "เข้าสู่ระบบสำเร็จ",
                        {
                            "access_token": access_token,
                            "data": user_dict,
                            "bypass_otp": True,
                            "device_token": refreshed_device_token,
                        }
                    )

            await _record_login_history(
                session, uid=user.uid, provider="password", ip=ip,
                user_agent=user_agent, status="otp_required",
            )
            await session.commit()

            login_uid = str(user.uid)
            login_email = user.email

        token = create_token(
            subject=login_uid,
            token_type="login",
            expires_minutes=5
        )

        return await OTPService.create_otp_session(
            action="login",
            identifier=login_uid,
            token=token,
            email=login_email
        )

    @staticmethod
    async def login_confirm(body, user_agent, ip):
        if _ip_rate_limited("auth:login-confirm", ip):
            return error(AuthStatus.RATE_LIMITED, "คุณพยายามยืนยันบ่อยเกินไป กรุณาลองอีกครั้งภายหลัง")

        payload, err = TokenService.verify_token(body.token, "login")
        if err:
            return err

        outcome, detail = OTPService.verify_otp("login", body.token, body.otp, identifier=payload.get("sub"))
        if outcome != "ok":
            return _otp_error_response(outcome, detail)

        from utils.uuid import parse_uuid
        try:
            uid = parse_uuid(payload["sub"])
        except (TypeError, ValueError):
            return error(AuthStatus.TOKEN_INVALID, "ข้อมูลผู้ใช้ในโทเค็นไม่ถูกต้อง")

        async with SessionLocal() as session:
            result = await session.execute(
                select(
                    User.uid,
                    User.email,
                    User.role,
                    User.username,
                    User.status,
                    User.created_at,
                ).where(User.uid == uid)
            )
            user = result.mappings().one_or_none()

            if not user:
                return error(AuthStatus.USER_NOT_FOUND, "ไม่พบผู้ใช้งานระบบ")

            await _record_login_history(
                session, uid=user.uid, provider="password", ip=ip,
                user_agent=user_agent, status="success",
            )
            await session.commit()

        deiveToken = _issue_device_token(user.uid, user.email)

        access_token = create_token(
            subject=str(user.uid),
            token_type="access",
            expires_minutes=60 * 24 * 7
        )

        refresh_token = create_token(
            subject=str(user.uid),
            token_type="refresh_token",
            expires_minutes=60 * 24 * 7
        )

        OTPService.clear_otp_session("login", body.token, str(user.uid))

        return success(
            AuthStatus.LOGIN_SUCCESS,
            "ยืนยันการเข้าสู่ระบบสำเร็จ",
            {"access_token": access_token, "data": {k: user[k] for k in user.keys()}, "deiveToken": deiveToken, "refresh_token": refresh_token}
        )

    @staticmethod
    async def register(body: RegisterParame, ip=None):
        if _ip_rate_limited("auth:register", ip):
            return error(AuthStatus.RATE_LIMITED, "คุณพยายามลงทะเบียนบ่อยเกินไป กรุณาลองอีกครั้งภายหลัง")

        normalized_email = normalize_email(body.email)

        if is_rate_limited("auth:otp-send", normalized_email, OTP_SEND_EMAIL_LIMIT, OTP_SEND_EMAIL_WINDOW_SECONDS):
            return error(AuthStatus.RATE_LIMITED, "คุณขอรหัส OTP บ่อยเกินไป กรุณาลองอีกครั้งภายหลัง")

        async with SessionLocal() as session:
            result = await session.execute(
                select(User).where(normalized_email_expr(User.email) == normalized_email)
            )
            if result.scalar_one_or_none():
                return error(
                    AuthStatus.USER_NOT_FOUND,
                    "มีอีเมลผู้ใช้งานนี้ในระบบแล้ว"
                )

        # The register JWT used to carry the plaintext password in its payload
        # (anyone holding the token could base64-decode it). Keep only the
        # email in the token and stage the credentials in Redis for exactly
        # the token's 5-minute lifetime instead.
        token = create_token(
            subject=normalized_email,
            token_type="register",
            expires_minutes=5,
        )

        if redis_client is not None:
            try:
                redis_client.setex(
                    f"register_data:{token}",
                    REGISTER_DATA_TTL_SECONDS,
                    json.dumps({"password": body.password, "username": body.username}),
                )
            except Exception as exc:
                print(f"[auth] unable to stage register data: {exc}")

        return await OTPService.create_otp_session(
            action="register",
            identifier=normalized_email,
            token=token,
            email=normalized_email
        )

    @staticmethod
    async def register_confirm(body: RegisterConfirmParame, ip=None):
        if _ip_rate_limited("auth:register-confirm", ip):
            return error(AuthStatus.RATE_LIMITED, "คุณพยายามยืนยันบ่อยเกินไป กรุณาลองอีกครั้งภายหลัง")

        payload, err = TokenService.verify_token(body.token, "register")
        if err:
            return err

        outcome, detail = OTPService.verify_otp("register", body.token, body.otp, identifier=payload.get("sub"))
        if outcome != "ok":
            return _otp_error_response(outcome, detail)

        register_data = _get_register_data(body.token)
        if register_data is None:
            return error(AuthStatus.TOKEN_INVALID, "หมดอายุ")

        async with SessionLocal() as session:
            new_user = User(
                username=register_data.get("username") or body.username or payload["sub"],
                email=payload["sub"],
                password=get_password_hash(register_data["password"]),
                role="user",
                status="active"
            )
            session.add(new_user)
            await session.commit()

        if redis_client is not None:
            try:
                redis_client.delete(f"register_data:{body.token}")
            except Exception:
                pass

        OTPService.clear_otp_session("register", body.token, payload["sub"])

        return success(
            AuthStatus.REGISTER_SUCCESS,
            "ลงทะเบียนผู้ใช้งานสำเร็จ"
        )

    @staticmethod
    async def reset(body: ResetPasswdParame, ip=None):
        if _ip_rate_limited("auth:reset-passwd", ip):
            return error(AuthStatus.RATE_LIMITED, "คุณร้องขอรีเซ็ตรหัสผ่านบ่อยเกินไป กรุณาลองอีกครั้งภายหลัง")

        if body.token and body.newPasswd:
            verifytoken = decode_token(body.token)
            if not verifytoken:
                return error(AuthStatus.TOKEN_INVALID, "โทเค็นไม่ถูกต้อง")
            if verifytoken.get("type") != 'access':
                return error(AuthStatus.TOKEN_WRONG_TYPE, "ประเภทโทเค็นไม่ถูกต้อง")
            from utils.uuid import parse_uuid
            try:
                uid = parse_uuid(verifytoken.get('sub'))
            except (TypeError, ValueError):
                return error(AuthStatus.TOKEN_INVALID, "ข้อมูลผู้ใช้ในโทเค็นไม่ถูกต้อง")
            async with SessionLocal() as session:
                result = await session.execute(
                    select(User).where(User.uid == uid)
                )
                user = result.scalar_one_or_none()
                if not user:
                    return error(AuthStatus.USER_NOT_FOUND, "ไม่พบผู้ใช้งานระบบ")
                # Changing password with an access token must re-authenticate
                # the holder with their CURRENT password, otherwise a stolen
                # access token alone would be enough to take over the account.
                if not body.oldPasswd or not verify_password(user.password, body.oldPasswd):
                    return error(AuthStatus.INVALID_CREDENTIALS, "ข้อมูลการเข้าสู่ระบบไม่ถูกต้อง")
                user.password = get_password_hash(body.newPasswd)
                await session.commit()
            return success(
                AuthStatus.PASSWORD_RESET_SUCCESS,
                "รีเซ็ตรหัสผ่านสำเร็จ"
            )
        else:
            normalized_email = normalize_email(body.email)

            if is_rate_limited("auth:otp-send", normalized_email, OTP_SEND_EMAIL_LIMIT, OTP_SEND_EMAIL_WINDOW_SECONDS):
                return error(AuthStatus.RATE_LIMITED, "คุณขอรหัส OTP บ่อยเกินไป กรุณาลองอีกครั้งภายหลัง")

            async with SessionLocal() as session:
                result = await session.execute(
                    select(User.uid, User.email).where(normalized_email_expr(User.email) == normalized_email)
                )
                user = result.mappings().one_or_none()
            if not user:
                # Anti-enumeration: answer exactly like the known-email path
                # (no OTP session is created and nothing is emailed).
                return success(
                    AuthStatus.OTP_SENT,
                    f"รหัส OTP ถูกส่งไปยังอีเมล {normalized_email}"
                )

            token = create_token(
                subject=str(user.uid),
                token_type="reset-passwd",
                expires_minutes=5,
            )

            return await OTPService.create_otp_session(
                action="reset-passwd",
                identifier=str(user.uid),
                token=token,
                email=user.email
            )

    @staticmethod
    async def reset_confirm(body, ip=None):
        if _ip_rate_limited("auth:reset-confirm", ip):
            return error(AuthStatus.RATE_LIMITED, "คุณพยายามยืนยันบ่อยเกินไป กรุณาลองอีกครั้งภายหลัง")

        payload, err = TokenService.verify_token(body.token, "reset-passwd")
        if err:
            return err

        outcome, detail = OTPService.verify_otp("reset-passwd", body.token, body.otp, identifier=payload.get("sub"))
        if outcome != "ok":
            return _otp_error_response(outcome, detail)

        from utils.uuid import parse_uuid
        try:
            uid = parse_uuid(payload["sub"])
        except (TypeError, ValueError):
            return error(AuthStatus.TOKEN_INVALID, "ข้อมูลผู้ใช้ในโทเค็นไม่ถูกต้อง")

        async with SessionLocal() as session:
            result = await session.execute(
                select(User).where(User.uid == uid)
            )
            user = result.scalar_one_or_none()
            if not user:
                return error(AuthStatus.USER_NOT_FOUND, "ไม่พบผู้ใช้งานระบบ")

            user.password = get_password_hash(body.newPasswd)
            await session.commit()

        OTPService.clear_otp_session("reset-passwd", body.token, str(uid))

        return success(
            AuthStatus.PASSWORD_RESET_SUCCESS,
            "รีเซ็ตรหัสผ่านสำเร็จ"
        )

    @staticmethod
    async def refresh_token(refresh_token: str):
        payload, err = TokenService.verify_token(refresh_token, "refresh_token")
        if err:
            return err

        # Rotation: a refresh token that has already been exchanged must never
        # be accepted again.
        if _is_refresh_token_used(refresh_token):
            return error(AuthStatus.TOKEN_INVALID, "โทเค็นถูกใช้งานแล้ว")

        from utils.uuid import parse_uuid
        try:
            uid = parse_uuid(payload["sub"])
        except (TypeError, ValueError):
            return error(AuthStatus.TOKEN_INVALID, "ข้อมูลผู้ใช้ในโทเค็นไม่ถูกต้อง")

        async with SessionLocal() as session:
            result = await session.execute(
                select(User.uid, User.status).where(User.uid == uid)
            )
            user = result.mappings().one_or_none()

        if not user:
            return error(AuthStatus.USER_NOT_FOUND, "ไม่พบผู้ใช้งานระบบ")

        if user.status.lower() != "active":
            return error(
                AuthStatus.USER_NOT_FOUND,
                "ผู้ใช้งานถูกระงับการใช้งาน กรุณาติดต่อผู้ดูแลระบบ"
            )

        _blacklist_refresh_token(refresh_token, payload)

        new_access_token = create_token(subject=str(uid), token_type="access", expires_minutes=60 * 24 * 7)
        new_refresh_token = create_token(subject=str(uid), token_type="refresh_token", expires_minutes=60 * 24 * 7)

        return success(
            AuthStatus.TOKEN_REFRESH_SUCCESS,
            "รีเฟรชโทเค็นสำเร็จ",
            {"access_token": new_access_token, "refresh_token": new_refresh_token}
        )