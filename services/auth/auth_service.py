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
from utils.jwt import create_token
from services.otp_service import OTPService

DEVICE_TOKEN_TTL_MINUTES = 60 * 24 * 7  # 7 days


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


class AuthService:

    @staticmethod
    async def login(body, user_agent, ip, deviceToken):
        async with SessionLocal() as session:
            result = await session.execute(
                select(User).where(User.email == body.email)
            )
            user = result.scalar_one_or_none()

            if not user:
                return error(AuthStatus.USER_NOT_FOUND, "ไม่พบผู้ใช้งานระบบ")

            if not user.password or not verify_password(user.password, body.password):
                return error(AuthStatus.INVALID_CREDENTIALS, "ข้อมูลการเข้าสู่ระบบไม่ถูกต้อง")

            # Accounts that also have any linked OAuth identity always
            # require OTP on password login, regardless of device-token
            # state - a stricter posture for higher-value/higher-risk
            # accounts capable of two different sign-in paths.
            oauth_link = await session.execute(
                select(OAuthAccount.id).where(OAuthAccount.uid == user.uid).limit(1)
            )
            has_linked_oauth = oauth_link.scalar_one_or_none() is not None

            if deviceToken and not has_linked_oauth:
                payload, err = TokenService.verify_token(deviceToken, "device")
                # Device token only bypasses OTP when it was issued for THIS
                # exact account (uid) AND the email it was bound to at
                # issuance still matches the email being logged into right
                # now - changing email always forces a fresh OTP challenge.
                if not err and payload.get("sub") == str(user.uid) and payload.get("email") == user.email:
                    access_token = create_token(
                        subject=str(user.uid),
                        token_type="access",
                        expires_minutes=60 * 24 * 7
                    )
                    # Rolling renewal: every successful bypass extends trust
                    # another 7 days rather than counting down from the
                    # original issuance.
                    refreshed_device_token = _issue_device_token(user.uid, user.email)

                    await _record_login_history(
                        session, uid=user.uid, provider="password", ip=ip,
                        user_agent=user_agent, status="success_device_bypass",
                    )
                    await session.commit()

                    user_dict = user.__dict__.copy()
                    user_dict.pop("password", None)
                    # remove SQLAlchemy internal state before returning
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
        payload, err = TokenService.verify_token(body.token, "login")
        if err:
            return err

        ok, otp_err = OTPService.verify_otp("login", body.token, body.otp)
        if not ok:
            return error(AuthStatus.OTP_INVALID, otp_err)

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

        # Device token embeds the account's email at issuance (see
        # _issue_device_token) - this is the one path a brand-new device
        # ever establishes trust through, since login()'s bypass check
        # requires a token that was already minted here or by an OAuth
        # callback.
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

# ================= REGISTER =================

    @staticmethod
    async def register(body: RegisterParame):
        async with SessionLocal() as session:
            result = await session.execute(
                select(User).where(User.email == body.email)
            )
            if result.scalar_one_or_none():
                return error(
                    AuthStatus.USER_NOT_FOUND,
                    "มีอีเมลผู้ใช้งานนี้ในระบบแล้ว"
                )

        token = create_token(
            subject=body.email,
            token_type="register",
            expires_minutes=5,
            extra_payload={"password": body.password, "username": body.username}
        )

        return await OTPService.create_otp_session(
            action="register",
            identifier=body.email,
            token=token,
            email=body.email
        )

    @staticmethod
    async def register_confirm(body: RegisterConfirmParame):
        payload, err = TokenService.verify_token(body.token, "register")
        if err:
            return err

        ok, otp_err = OTPService.verify_otp("register", body.token, body.otp)
        if not ok:
            return error(AuthStatus.OTP_INVALID, otp_err)

        async with SessionLocal() as session:
            new_user = User(
                username=payload.get("username") or body.username or payload["sub"],
                email=payload["sub"],
                password=get_password_hash(payload["password"]),
                role="user",
                status="active"
            )
            session.add(new_user)
            await session.commit()

        OTPService.clear_otp_session("register", body.token, payload["sub"])

        return success(
            AuthStatus.REGISTER_SUCCESS,
            "ลงทะเบียนผู้ใช้งานสำเร็จ"
        )

# ================= RESET =================

    @staticmethod
    async def reset(body: ResetPasswdParame):
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
                user.password = get_password_hash(body.newPasswd)
                await session.commit()
            return success(
                AuthStatus.PASSWORD_RESET_SUCCESS,
                "รีเซ็ตรหัสผ่านสำเร็จ"
            )
        else:
            async with SessionLocal() as session:
                result = await session.execute(
                    select(User.uid, User.email).where(User.email == body.email)
                )
                user = result.mappings().one_or_none()
            if not user:
                return error(AuthStatus.USER_NOT_FOUND, "ไม่พบผู้ใช้งานระบบ")

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
    async def reset_confirm(body):
        payload, err = TokenService.verify_token(body.token, "reset-passwd")
        if err:
            return err

        ok, otp_err = OTPService.verify_otp("reset-passwd", body.token, body.otp)
        if not ok:
            return error(AuthStatus.OTP_INVALID, otp_err)

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

        new_access_token = create_token(subject=str(uid), token_type="access", expires_minutes=60 * 24 * 7)
        new_refresh_token = create_token(subject=str(uid), token_type="refresh_token", expires_minutes=60 * 24 * 7)

        return success(
            AuthStatus.TOKEN_REFRESH_SUCCESS,
            "รีเฟรชโทเค็นสำเร็จ",
            {"access_token": new_access_token, "refresh_token": new_refresh_token}
        )