"""One-Time-Password issuing + verification for the password-auth flow.

The OTP is a 6-digit code stored in Redis under ``otp:{action}:{token}`` with a
short TTL. Delivery is a real e-mail when ``SMTP_*`` env vars are configured;
otherwise (dev) the code is printed to the server console so the flow can be
tested end-to-end without a mail server.
"""

import os
import random
import smtplib
from email.mime.text import MIMEText

from utils.response import success
from utils.status_code import AuthStatus

try:
    from cores.redis import redis_client
except Exception:  # pragma: no cover - import guard
    redis_client = None

OTP_TTL_SECONDS = 300  # 5 minutes


class OTPService:

    @staticmethod
    def _generate() -> str:
        return f"{random.randint(100000, 999999)}"

    @staticmethod
    def _key(action: str, token: str) -> str:
        return f"otp:{action}:{token}"

    @staticmethod
    async def create_otp_session(action: str, identifier: str, token: str, email: str):
        """Issue + store an OTP (and e-mail it), returning the envelope the
        frontend needs to complete the next /confirm step (`data.token`)."""
        otp = OTPService._generate()
        if redis_client is not None:
            try:
                redis_client.setex(OTPService._key(action, token), OTP_TTL_SECONDS, otp)
            except Exception as error:
                print(f"[OTP] unable to store session {action}:{token}: {error}")
        OTPService._send_email(email, otp, action)
        return success(
            AuthStatus.OTP_SENT,
            f"รหัส OTP ถูกส่งไปยังอีเมล {email}",
            {"token": token, "expires_in": OTP_TTL_SECONDS},
        )

    @staticmethod
    def verify_otp(action: str, token: str, otp: str) -> tuple[bool, str | None]:
        if redis_client is None:
            return False, "OTP service unavailable"
        try:
            stored = redis_client.get(OTPService._key(action, token))
        except Exception as error:
            print(f"[OTP] verify error {action}:{token}: {error}")
            return False, "รหัส OTP ไม่ถูกต้องหรือหมดอายุ"
        if stored:
            value = stored.decode() if isinstance(stored, bytes) else str(stored)
            if value == otp:
                return True, None
        return False, "รหัส OTP ไม่ถูกต้องหรือหมดอายุ"

    @staticmethod
    def clear_otp_session(action: str, token: str, identifier: str) -> None:
        if redis_client is None:
            return
        try:
            redis_client.delete(OTPService._key(action, token))
        except Exception:
            pass

    @staticmethod
    def _send_email(email: str, otp: str, action: str) -> None:
        host = os.getenv("SMTP_HOST")
        if not host:
            # Dev fallback so the flow is testable without a mail server.
            print(f"[OTP] {action} code for {email}: {otp}")
            return
        try:
            port = int(os.getenv("SMTP_PORT", "587"))
            user = os.getenv("SMTP_USER")
            pw = os.getenv("SMTP_PASSWORD")
            sender = os.getenv("SMTP_FROM", user)
            msg = MIMEText(
                f"รหัสยืนยัน (OTP) ของคุณคือ: {otp}\n\nรหัสนี้จะหมดอายุใน 5 นาที",
                "plain",
                "utf-8",
            )
            msg["Subject"] = f"รหัส OTP ของคุณ ({action})"
            msg["From"] = sender
            msg["To"] = email
            with smtplib.SMTP(host, port, timeout=15) as server:
                server.starttls()
                if user:
                    server.login(user, pw)
                server.sendmail(sender, [email], msg.as_string())
        except Exception as error:
            print(f"[OTP] email send failed (dev code for {email}: {otp}): {error}")