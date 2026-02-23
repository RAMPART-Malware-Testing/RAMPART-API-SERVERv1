import ssl

from cores.redis import redis_client
import random
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

OTP_TTL = 300
OTP_ATTEMPT_LIMIT = 5

class OTPService:

    @staticmethod
    def generate_otp():
        return f"{random.randint(100000, 999999)}"

    @staticmethod
    async def send_email_otp(email: str, otp: str):
        sender_email = os.getenv("GMAIL_USERNAME")
        app_password = os.getenv("GMAIL_PASSWORD")

        message = MIMEMultipart()
        message["Subject"] = "Your OTP Code"
        message["From"] = sender_email
        message["To"] = email

        body = f"""
        Your OTP Code is: {otp}

        This code will expire in 5 minutes.
        """

        message.attach(MIMEText(body, "plain"))

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, app_password)
            server.sendmail(sender_email, email, message.as_string())

        return {"message": "OTP sent successfully"}

    @staticmethod
    def _otp_key(action: str, token: str):
        return f"otp:{action}:{token}"

    @staticmethod
    def _attempt_key(token: str):
        return f"otp_attempt:{token}"

    @staticmethod
    def _lock_key(action: str, identifier: str):
        return f"otp_lock:{action}:{identifier}"

    @classmethod
    async def create_otp_session(cls, action: str, identifier: str, token: str, email: str):

        session_key = f"otp_session:{action}:{identifier}"

        existing_token = redis_client.get(session_key)
        if existing_token:
            ttl = redis_client.ttl(session_key)
            return {
                "success": True,
                "status": "OTP_ALREADY_SENT",
                "message": "OTP was already sent. Please check your email.",
                "data": {
                    "token": existing_token,
                    "expires_in": ttl
                }
            }

        otp = cls.generate_otp()
        print(f'OTP ==> {otp}')

        redis_client.setex(cls._otp_key(action, token), OTP_TTL, otp)
        redis_client.setex(cls._attempt_key(token), OTP_TTL, 0)
        redis_client.setex(session_key, OTP_TTL, token)

        await cls.send_email_otp(email, otp)

        return {
            "success": True,
            "status": "OTP_SENT",
            "message": "OTP has been sent to your email.",
            "data": {
                "token": token,
                "expires_in": OTP_TTL
            }
        }

    @classmethod
    def verify_otp(cls, action: str, token: str, otp_input: str):

        otp_key = cls._otp_key(action, token)
        correct_otp = redis_client.get(otp_key)

        if not correct_otp:
            return False, "OTP expired"

        attempt_key = cls._attempt_key(token)
        attempts = int(redis_client.get(attempt_key) or 0)

        if attempts >= OTP_ATTEMPT_LIMIT:
            return False, "Too many attempts"

        if otp_input != correct_otp:
            redis_client.incr(attempt_key)
            return False, "Invalid OTP"

        return True, None

    @classmethod
    def clear_otp_session(cls, action: str, token: str, identifier: str):
        redis_client.delete(
            cls._otp_key(action, token),
            cls._attempt_key(token),
            f"otp_session:{action}:{identifier}"
        )