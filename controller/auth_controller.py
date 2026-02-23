from services.auth_service import AuthService
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
        subject=str(uid),           # ⭐ uid เป็นหลัก
        token_type="access",
        expires_minutes=ACCESS_TOKEN_EXPIRE_MINUTES,
        extra_payload={
            "username": username    # เอาไว้ใช้แสดงผล / debug
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

async def resetPasswd_controller(user: ResetPasswdParame, user_agent: str, ip: str):
    async with SessionLocal() as session:
        result = await session.execute(
            select(User).where(User.username == user.username)
        )
        db_user = result.scalar_one_or_none()

    if not db_user or not verify_password(db_user.password, user.password):
        return {"success": False, "message": "Invalid credentials"}

    uid = db_user.uid

    device_hash = generate_device_hash(user_agent, ip)
    device_key = f"device:{uid}:{device_hash}"

    if redis_client.exists(device_key):
        ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7
        access_token = generate_accesstoken(
            uid, db_user.username, ACCESS_TOKEN_EXPIRE_MINUTES
        )
        return {
            "success": True,
            "token": access_token,
            "message": "Login successful (trusted device)",
            "otp_required": False
        }

    existing_token = redis_client.get(f"user_login:{uid}")
    if existing_token:
        ttl = redis_client.ttl(f"login:{existing_token}")
        return {
            "success": True,
            "token": existing_token,
            "expires_in": ttl,
            "otp_required": True
        }

    token = create_token(
        subject=str(uid),
        token_type="login_confirm",
        expires_minutes=5
    )

    otp = generate_otp()

    redis_client.setex(f"login:{token}", LOGIN_TTL, uid)
    redis_client.setex(f"login:otp:{token}", LOGIN_TTL, otp)
    redis_client.setex(f"user_login:{uid}", LOGIN_TTL, token)
    redis_client.setex(f"login:attempt:{token}", LOGIN_TTL, 0)

    return {
        "otp": otp,
        "success": True,
        "token": token,
        "expires_in": LOGIN_TTL,
        "otp_required": True
    }

async def resetPasswd_confirm_controller(data: ResetPasswdConfirmParame, user_agent: str, ip: str):
    try:
        payload = decode_token(data.token)
        if payload["type"] != "login_confirm":
            return {"success": False, "message": "Token is not supported"}
    except ValueError:
        return {"success": False, "message": "Invalid or expired token"}

    redis_key = f"login:{data.token}"
    uid = redis_client.get(redis_key)

    if not uid:
        return {"success": False, "message": "Login session expired"}

    uid = int(uid)

    attempt_key = f"login:attempt:{data.token}"
    attempts = int(redis_client.get(attempt_key) or 0)

    if attempts >= OTP_ATTEMPT_LIMIT:
        ttl = redis_client.ttl(redis_key)
        return {
            "success": False,
            "message": f"Too many attempts. Try again in {ttl // 60} minutes."
        }

    otp_key = f"login:otp:{data.token}"
    correct_otp = redis_client.get(otp_key)

    if data.otp != correct_otp:
        redis_client.incr(attempt_key)
        return {
            "success": False,
            "message": f"Invalid OTP ({attempts + 1}/{OTP_ATTEMPT_LIMIT})"
        }

    device_hash = generate_device_hash(user_agent, ip)
    redis_client.setex(
        f"device:{uid}:{device_hash}",
        60 * 60 * 24 * 7,
        "trusted"
    )

    async with SessionLocal() as session:
        user = await session.get(User, uid)

    ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7
    access_token = generate_accesstoken(
        uid, user.username, ACCESS_TOKEN_EXPIRE_MINUTES
    )

    redis_client.delete(
        redis_key,
        otp_key,
        attempt_key,
        f"user_login:{uid}"
    )

    return {
        "success": True,
        "access_token": access_token,
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }


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

