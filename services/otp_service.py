import random
from typing import Literal

from utils.mailer import send_email
from utils.response import error, success
from utils.status_code import AuthStatus

try:
    from cores.redis import redis_client
except Exception:
    redis_client = None

OTP_TTL_SECONDS = 300
MAX_OTP_ATTEMPTS = 5

VerifyOutcome = Literal["ok", "wrong", "locked", "expired"]


class OTPService:

    @staticmethod
    def _generate() -> str:
        return f"{random.randint(100000, 999999)}"

    @staticmethod
    def _key(action: str, token: str) -> str:
        return f"otp:{action}:{token}"

    @staticmethod
    def _attempts_key(action: str, token: str) -> str:
        return f"otp_attempts:{action}:{token}"

    @staticmethod
    def _lockout_key(action: str, identifier: str) -> str:
        return f"otp_lockout:{action}:{identifier}"

    @staticmethod
    async def create_otp_session(action: str, identifier: str, token: str, email: str):
        if redis_client is not None:
            try:
                lockout_ttl = redis_client.ttl(OTPService._lockout_key(action, identifier))
            except Exception as exc:
                print(f"[OTP] lockout check failed for {action}:{identifier}: {exc}")
                lockout_ttl = None
            if isinstance(lockout_ttl, int) and lockout_ttl > 0:
                return error(
                    AuthStatus.OTP_LOCKED,
                    f"คุณกรอกรหัส OTP ผิดครบ {MAX_OTP_ATTEMPTS} ครั้งแล้ว "
                    f"กรุณารออีก {lockout_ttl} วินาทีแล้วลองใหม่",
                    {"locked_seconds_remaining": lockout_ttl},
                )

        otp = OTPService._generate()
        if redis_client is not None:
            try:
                redis_client.setex(OTPService._key(action, token), OTP_TTL_SECONDS, otp)
                # Reset any stale attempt counter from a prior session that
                # happened to reuse this exact token (practically
                # impossible given tokens are fresh JWTs, but cheap
                # insurance against ever starting a new session already
                # "half locked out").
                redis_client.delete(OTPService._attempts_key(action, token))
            except Exception as exc:
                print(f"[OTP] unable to store session {action}:{token}: {exc}")
        OTPService._send_email(email, otp, action)
        return success(
            AuthStatus.OTP_SENT,
            f"รหัส OTP ถูกส่งไปยังอีเมล {email}",
            {"token": token, "expires_in": OTP_TTL_SECONDS},
        )

    @staticmethod
    def verify_otp(action: str, token: str, otp: str, identifier: str | None = None) -> tuple[VerifyOutcome, int | None]:
        if redis_client is None:
            return "expired", None

        attempts_key = OTPService._attempts_key(action, token)
        try:
            current_attempts = redis_client.get(attempts_key)
            current_attempts = int(current_attempts) if current_attempts is not None else 0
        except Exception as error:
            print(f"[OTP] attempts read error {action}:{token}: {error}")
            current_attempts = 0

        if current_attempts >= MAX_OTP_ATTEMPTS:
            try:
                remaining = redis_client.ttl(attempts_key)
            except Exception:
                remaining = None
            remaining = remaining if isinstance(remaining, int) and remaining > 0 else None
            return "locked", remaining

        try:
            stored = redis_client.get(OTPService._key(action, token))
        except Exception as error:
            print(f"[OTP] verify error {action}:{token}: {error}")
            return "expired", None

        if not stored:
            return "expired", None

        value = stored.decode() if isinstance(stored, bytes) else str(stored)
        if value == otp:
            return "ok", None

        new_count = current_attempts + 1
        try:
            ttl = redis_client.ttl(OTPService._key(action, token))
            ttl = ttl if isinstance(ttl, int) and ttl > 0 else OTP_TTL_SECONDS
            redis_client.setex(attempts_key, ttl, new_count)

            if new_count >= MAX_OTP_ATTEMPTS and identifier:
                redis_client.setex(OTPService._lockout_key(action, identifier), ttl, "1")
        except Exception as error:
            print(f"[OTP] unable to record failed attempt {action}:{token}: {error}")

        attempts_remaining = max(0, MAX_OTP_ATTEMPTS - new_count)
        return "wrong", attempts_remaining

    @staticmethod
    def clear_otp_session(action: str, token: str, identifier: str) -> None:
        if redis_client is None:
            return
        try:
            redis_client.delete(OTPService._key(action, token))
            redis_client.delete(OTPService._attempts_key(action, token))
        except Exception:
            pass

    @staticmethod
    def _send_email(email: str, otp: str, action: str) -> None:
        send_email(
            email,
            f"รหัส OTP ของคุณ ({action})",
            f"รหัสยืนยัน (OTP) ของคุณคือ: {otp}\n\nรหัสนี้จะหมดอายุใน 5 นาที",
        )
