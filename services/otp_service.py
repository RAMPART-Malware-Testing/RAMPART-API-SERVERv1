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
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>OTP Code</title>
                <style>
                    .countdown-timer {{
                        font-size: 24px;
                        font-weight: bold;
                        color: #e74c3c;
                        background-color: #fff5f5;
                        display: inline-block;
                        padding: 8px 20px;
                        border-radius: 50px;
                        margin-top: 10px;
                    }}
                    .expired-message {{
                        color: #e74c3c;
                        font-weight: bold;
                        margin-top: 15px;
                        padding: 10px;
                        background-color: #ffeaea;
                        border-radius: 8px;
                        display: none;
                    }}
                    .otp-box {{
                        background-color: #f0f4ff;
                        padding: 20px;
                        border-radius: 12px;
                        margin: 30px 0;
                        display: inline-block;
                        width: auto;
                        cursor: pointer;
                    }}
                    .otp-code {{
                        font-size: 42px;
                        font-weight: bold;
                        letter-spacing: 8px;
                        color: #4A6CF7;
                        font-family: monospace;
                    }}
                </style>
            </head>
            <body style="margin: 0; padding: 0; font-family: Arial, Helvetica, sans-serif; background-color: #f4f4f7;">
                <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; background-color: #f4f4f7; padding: 20px;">
                    <tr>
                        <td align="center">
                            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #ffffff; border-radius: 16px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); overflow: hidden;">
                                <tr>
                                    <td style="background-color: #393e50; padding: 30px 20px; text-align: center;">
                                        <h1 style="color: #ffffff; margin: 0; font-size: 28px;">OTP Verification</h1>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding: 40px 30px; text-align: center;">
                                        <p style="font-size: 18px; color: #333333; margin-bottom: 30px;">Hello, {email}</p>
                                        <p style="font-size: 16px; color: #555555; margin-bottom: 20px;">Use the following One-Time Password (OTP) to complete your verification:</p>

                                        <div class="otp-box" id="otpBox">
                                            <span class="otp-code" id="otpCode">{otp}</span>
                                        </div>

                                        <div style="margin: 20px 0;">
                                            <p style="font-size: 14px; color: #666666; margin-bottom: 5px;">This code will expire in:</p>
                                            <div class="countdown-timer" id="timer"> 5 minute</div>
                                            <div class="expired-message" id="expiredMessage">
                                                This OTP has expired. Please request a new one.
                                            </div>
                                        </div>

                                        <p style="font-size: 12px; color: #999999; margin-top: 10px;">
                                            <span id="statusText">Code is valid</span>
                                        </p>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="background-color: #f9f9fb; padding: 20px; text-align: center; border-top: 1px solid #eeeeee;">
                                        <p style="font-size: 12px; color: #aaaaaa; margin: 0;">
                                            If you didn't request this code, please ignore this email.
                                        </p>
                                        <p style="font-size: 12px; color: #aaaaaa; margin-top: 10px;">
                                            &copy; 2025 RAMPART. All rights reserved.
                                        </p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </body>
            </html>
            """

        message.attach(MIMEText(body, "html"))

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