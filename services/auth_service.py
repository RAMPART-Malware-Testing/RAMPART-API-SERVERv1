from services.token_service import TokenService
from utils.jwt import decode_token, get_token_type, get_token_subject
from utils.response import error, success
from utils.status_code import AuthStatus

def verify_access_token(token: str) -> str:
    payload = decode_token(token)

    if get_token_type(payload) != "access":
        raise ValueError("Invalid token type")

    uid = get_token_subject(payload)
    if not uid:
        raise ValueError("Invalid token payload")

    return uid


from sqlalchemy import select
from cores.async_pg_db import SessionLocal
from cores.models_class import User
from utils.cypto.PasswordCreateAndVerify import get_password_hash, verify_password
from utils.jwt import create_token, decode_token
from services.otp_service import OTPService
from services.device_service import DeviceService


class AuthService:

    @staticmethod
    async def login(body, user_agent, ip):
        async with SessionLocal() as session:
            result = await session.execute(
                select(User).where(User.username == body.username)
            )
            user = result.scalar_one_or_none()

        if not user:
            return error(AuthStatus.USER_NOT_FOUND, "User not found.")

        if not verify_password(user.password, body.password):
            return error(AuthStatus.INVALID_CREDENTIALS, "Invalid credentials.")

        if DeviceService.is_trusted(user.uid, user_agent, ip):
            access_token = create_token(
                subject=str(user.uid),
                token_type="access",
                expires_minutes=60 * 24 * 7
            )

            return success(
                AuthStatus.LOGIN_SUCCESS,
                "Login successful.",
                {"access_token": access_token}
            )

        token = create_token(
            subject=str(user.uid),
            token_type="login",
            expires_minutes=5
        )

        return await OTPService.create_otp_session(
            action="login",
            identifier=str(user.uid),
            token=token,
            email=user.username
        )

    @staticmethod
    async def login_confirm(body, user_agent, ip):

        payload, err = TokenService.verify_token(body.token, "login")
        if err:
            return err

        ok, otp_err = OTPService.verify_otp("login", body.token, body.otp)
        if not ok:
            return error(AuthStatus.OTP_INVALID, otp_err)

        uid = int(payload["sub"])

        DeviceService.remember_device(uid, user_agent, ip)

        access_token = create_token(
            subject=str(uid),
            token_type="access",
            expires_minutes=60 * 24 * 7
        )

        OTPService.clear_otp_session("login", body.token, str(uid))

        return success(
            AuthStatus.LOGIN_SUCCESS,
            "Login confirmed successfully.",
            {"access_token": access_token}
        )

# ================= REGISTER =================

    @staticmethod
    async def register(body):

        async with SessionLocal() as session:
            result = await session.execute(
                select(User).where(User.username == body.username)
            )
            if result.scalar_one_or_none():
                return error(
                    AuthStatus.INVALID_CREDENTIALS,
                    "User already exists."
                )

        token = create_token(
            subject=body.username,
            token_type="register",
            expires_minutes=5,
            extra_payload={"password": body.password}
        )

        return await OTPService.create_otp_session(
            action="register",
            identifier=body.username,
            token=token,
            email=body.username
        )

    @staticmethod
    async def register_confirm(data):

        payload, err = TokenService.verify_token(data.token, "register")
        if err:
            return err

        ok, otp_err = OTPService.verify_otp("register", data.token, data.otp)
        if not ok:
            return error(AuthStatus.OTP_INVALID, otp_err)

        async with SessionLocal() as session:
            new_user = User(
                username=payload["sub"],
                email=payload["sub"],
                password=get_password_hash(payload["password"]),
                role="user",
                status="active"
            )
            session.add(new_user)
            await session.commit()

        OTPService.clear_otp_session("register", data.token, payload["sub"])

        return success(
            AuthStatus.REGISTER_SUCCESS,
            "User registered successfully."
        )

# ================= RESET =================

    @staticmethod
    async def reset_confirm(data):

        payload, err = TokenService.verify_token(data.token, "reset")
        if err:
            return err

        ok, otp_err = OTPService.verify_otp("reset", data.token, data.otp)
        if not ok:
            return error(AuthStatus.OTP_INVALID, otp_err)

        async with SessionLocal() as session:
            result = await session.execute(
                select(User).where(User.username == payload["sub"])
            )
            user = result.scalar_one()
            user.password = get_password_hash(data.newPasswd)
            await session.commit()

        OTPService.clear_otp_session("reset", data.token, payload["sub"])

        return success(
            AuthStatus.PASSWORD_RESET_SUCCESS,
            "Password reset successfully."
        )

    @staticmethod
    async def reset_confirm(data):

        payload, err = TokenService.verify_token(data.token, "reset")
        if err:
            return err

        ok, otp_err = OTPService.verify_otp("reset", data.token, data.otp)
        if not ok:
            return error(AuthStatus.OTP_INVALID, otp_err)

        async with SessionLocal() as session:
            result = await session.execute(
                select(User).where(User.username == payload["sub"])
            )
            user = result.scalar_one()
            user.password = get_password_hash(data.newPasswd)
            await session.commit()

        OTPService.clear_otp_session("reset", data.token, payload["sub"])

        return success(
            AuthStatus.PASSWORD_RESET_SUCCESS,
            "Password reset successfully."
        )
    
