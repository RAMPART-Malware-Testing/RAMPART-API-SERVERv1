import secrets

from fastapi import HTTPException
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError

from cores.Schema.schema_class import User
from utils.cypto.PasswordCreateAndVerify import get_password_hash
from utils.jwt import create_token


class TestModeService:
    def __init__(self, session_factory, redis, username: str, email: str):
        self.session_factory = session_factory
        self.redis = redis
        self.username = username
        self.email = email

    async def _users(self, session):
        result = await session.execute(
            select(User).where(or_(User.username == self.username, func.lower(User.email) == self.email))
        )
        return result.scalars().all()

    def _state(self, users):
        if not users:
            return "missing", None
        if len(users) != 1:
            return "conflicting", None
        user = users[0]
        if user.username != self.username or user.email.lower() != self.email or user.role != "test":
            return "conflicting", None
        return ("active" if user.status == "active" else "inactive"), user

    async def status(self):
        try:
            async with self.session_factory() as session:
                state, _ = self._state(await self._users(session))
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Test database is unavailable.") from exc
        try:
            redis_ready = bool(await run_in_threadpool(self.redis.ping))
        except Exception:
            redis_ready = False
        return {"test_mode": True, "database": True, "redis": redis_ready, "user": state}

    async def create_user(self):
        try:
            async with self.session_factory() as session:
                state, user = self._state(await self._users(session))
                if state == "conflicting":
                    raise HTTPException(status_code=409, detail="Configured test identity conflicts with an existing user.")
                if state == "active":
                    return "existing", user
                if state == "inactive":
                    user.status = "active"
                    await session.commit()
                    return "reactivated", user
                user = User(
                    username=self.username,
                    email=self.email,
                    password=get_password_hash(secrets.token_urlsafe(48)),
                    role="test",
                    status="active",
                )
                session.add(user)
                await session.commit()
                return "created", user
        except HTTPException:
            raise
        except IntegrityError as exc:
            await session.rollback()
            try:
                state, user = self._state(await self._users(session))
                if state == "active":
                    return "existing", user
                if state == "inactive":
                    user.status = "active"
                    await session.commit()
                    return "reactivated", user
            except Exception as retry_exc:
                raise HTTPException(status_code=503, detail="Test database is unavailable.") from retry_exc
            raise HTTPException(status_code=409, detail="Configured test identity conflicts with an existing user.") from exc
        except Exception as exc:
            if "session" in locals():
                await session.rollback()
            raise HTTPException(status_code=503, detail="Test database is unavailable.") from exc

    async def issue_tokens(self):
        try:
            async with self.session_factory() as session:
                state, user = self._state(await self._users(session))
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Test database is unavailable.") from exc
        if state == "missing":
            raise HTTPException(status_code=404, detail="Test user does not exist.")
        if state != "active":
            raise HTTPException(status_code=409, detail="Test user is not active or conflicts with an existing user.")
        uid = str(user.uid)
        access_token = create_token(subject=uid, token_type="access", expires_minutes=60)
        upload_token = create_token(subject=uid, token_type="upload", expires_minutes=15)
        try:
            await run_in_threadpool(self.redis.setex, f"upload_session:{uid}", 900, upload_token)
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Test Redis is unavailable.") from exc
        return {"access_token": access_token, "upload_token": upload_token, "token_type": "bearer", "expires_in": 900}
