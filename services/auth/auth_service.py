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
from cores.models_class import User
from utils.cypto.PasswordCreateAndVerify import get_password_hash, verify_password
from utils.jwt import create_token, decode_token
from services.otp_service import OTPService


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

        if not verify_password(user.password, body.password):
            return error(AuthStatus.INVALID_CREDENTIALS, "ข้อมูลการเข้าสู่ระบบไม่ถูกต้อง")

        if deviceToken: 
            payload, err = TokenService.verify_token(deviceToken, "device")
            if not err:
                access_token = create_token(
                    subject=str(user.uid),
                    token_type="access",
                    expires_minutes=60 * 24 * 7
                )

                user_dict = user.__dict__.copy()
                user_dict.pop("password", None)
                user = user_dict 
                return success(
                    AuthStatus.LOGIN_SUCCESS,
                    "เข้าสู่ระบบสำเร็จ",
                    { "access_token": access_token, "data":user, "bypass_otp":True }
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
            email=user.email
        )

    @staticmethod
    async def login_confirm(body, user_agent, ip):

        payload, err = TokenService.verify_token(body.token, "login")
        if err:
            return err

        ok, otp_err = OTPService.verify_otp("login", body.token, body.otp)
        if not ok:
            return error(AuthStatus.OTP_INVALID, otp_err) # อาจจะต้องไปแปลเพิ่มใน OTPService หากมีการส่ง error ออกมาจากตรงนั้น

        uid = int(payload["sub"])

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

        deiveToken = create_token(
            subject=str(user.uid),
            token_type="device",
            expires_minutes=60*24*7
        )

        access_token = create_token(
            subject=str(uid),
            token_type="access",
            expires_minutes=60 * 24 * 7
        )

        OTPService.clear_otp_session("login", body.token, str(uid))

        return success(
            AuthStatus.LOGIN_SUCCESS,
            "ยืนยันการเข้าสู่ระบบสำเร็จ",
            {"access_token": access_token, "data":user, "deiveToken":deiveToken}
        )

# ================= REGISTER =================

    @staticmethod
    async def register(body:RegisterParame):

        async with SessionLocal() as session:
            result = await session.execute(
                select(User).where(User.email == body.email)
            )
            if result.scalar_one_or_none():
                return error(
                    AuthStatus.INVALID_CREDENTIALS,
                    "มีอีเมลผู้ใช้งานนี้ในระบบแล้ว"
                )

        token = create_token(
            subject=body.email,
            token_type="register",
            expires_minutes=5,
            extra_payload={"password": body.password}
        )

        return await OTPService.create_otp_session(
            action="register",
            identifier=body.email,
            token=token,
            email=body.email
        )

    @staticmethod
    async def register_confirm(body:RegisterConfirmParame):

        payload, err = TokenService.verify_token(body.token, "register")
        if err:
            return err

        ok, otp_err = OTPService.verify_otp("register", body.token, body.otp)
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

        OTPService.clear_otp_session("register", body.token, payload["sub"])

        return success(
            AuthStatus.REGISTER_SUCCESS,
            "ลงทะเบียนผู้ใช้งานสำเร็จ"
        )

# ================= RESET =================

    @staticmethod
    async def reset(body:ResetPasswdParame):
        if body.token and body.newPasswd:
            verifytoken = decode_token(body.token)
            if not verifytoken: return error(AuthStatus.TOKEN_INVALID, "โทเค็นไม่ถูกต้อง")
            if verifytoken.get("type") != 'access': return error(AuthStatus.TOKEN_WRONG_TYPE, "ประเภทโทเค็นไม่ถูกต้อง")
            uid = int(verifytoken.get('sub'))
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
                    select(User.uid,User.email).where(User.email == body.email)
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

        uid = int(payload["sub"])

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