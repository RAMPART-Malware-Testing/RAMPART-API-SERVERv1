from services.auth.auth_service import AuthService
from sqlalchemy import select
from cores.async_pg_db import SessionLocal
from cores.models_class import User
from schemas.auth import LoginParame, LoginConfirmParame, RegisterParame, RegisterConfirmParame, ResetPasswdParame, ResetPasswdConfirmParame
from utils.cypto.PasswordCreateAndVerify import verify_password
from utils.jwt import create_token, decode_token
from cores.redis import redis_client
import json

import random
import hashlib

def generate_otp() -> str:
    return f"{random.randint(100000, 999999)}"

def generate_device_hash(user_agent: str, ip: str) -> str:
    raw = f"{user_agent}:{ip}"
    return hashlib.sha256(raw.encode()).hexdigest()

def generate_accesstoken(
    uid: int,
    username: str,
    ACCESS_TOKEN_EXPIRE_MINUTES: int
):
    access_token = create_token(
        subject=str(uid),
        token_type="access",
        expires_minutes=ACCESS_TOKEN_EXPIRE_MINUTES,
        extra_payload={
            "username": username
        }
    )
    return access_token

LOGIN_TTL = 300
OTP_ATTEMPT_LIMIT = 5

async def login_controller(body:LoginParame, user_agent:str, ip:str):
    response = await AuthService.login(body, user_agent, ip)
    return response

async def login_confirm_controller(body: LoginConfirmParame, user_agent: str, ip: str):
    response = await AuthService.login_confirm(body, user_agent, ip)
    return response

async def register_controller(body:RegisterParame):
    response = await AuthService.register(body)
    return response

async def register_confirm_controller(body:RegisterConfirmParame):
    response = await AuthService.register_confirm(body)
    return response

async def resetPasswd_controller(body: ResetPasswdParame):
    response = await AuthService.reset(body)
    return response

async def resetPasswd_confirm_controller(body: ResetPasswdConfirmParame):
    response = await AuthService.reset_confirm(body)
    return response


from fastapi import HTTPException

async def access_token_controller(uid: int):
    async with SessionLocal() as session:
        uid = int(uid)
        user = await session.get(User, uid)


        if not user:
            return {
                "success": False,
                "message": "User not found"
            }

        return {
            "success": True,
            "user": {
                "uid": user.uid,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "created_at": user.created_at
            }
        }

