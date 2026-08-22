import inspect
import json
from pathlib import Path

from fastapi import HTTPException
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError

from cores.Schema.schema_class import Analysis, Reports, User
from utils.jwt import create_token


class TestModeService:
    def __init__(self, session_factory, redis, username: str, email: str):
        self.session_factory = session_factory
        self.redis = redis
        self.username = username
        self.email = email
        self.reports_dir = Path("reports")

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
                    avatar_url=None,
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

    async def analysis_snapshot(self, task_id: str):
        async with self.session_factory() as session:
            result = await session.execute(
                select(Analysis, Reports)
                .outerjoin(Reports, Analysis.rid == Reports.rid)
                .where(Analysis.task_id == task_id)
                .limit(1)
            )
            row = result.first()
        if row is None:
            return None
        analysis, report = row
        return {
            "status": analysis.status,
            "tools": analysis.tools,
            "md5": analysis.md5,
            "file_name": analysis.file_name,
            "file_type": analysis.file_type,
            "file_size": analysis.file_size,
            "file_hash": analysis.file_hash,
            "rid": str(analysis.rid) if analysis.rid else None,
            "is_malicious": analysis.is_malicious,
            "blocked_by": analysis.blocked_by,
            "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
            "scores": None if report is None else {
                "virustotal": float(report.virustotal_score) if report.virustotal_score is not None else None,
                "mobsf": float(report.mobsf_score) if report.mobsf_score is not None else None,
                "cape": float(report.cape_score) if report.cape_score is not None else None,
                "gemini": float(report.score) if report.score is not None else None,
                "rampart_ai": float(report.rampart_score) if report.rampart_score is not None else None,
            },
            "assessment": None if report is None else {
                "risk_level": report.risk_level,
                "summary": report.analysis_summary,
                "recommendation": report.recommendation,
                "verdict": report.gemini_recommendation,
                "indicators": report.risk_indicators,
            },
        }

    async def analysis_diagnostics(self, task_id: str):
        try:
            snapshot = self.analysis_snapshot(task_id)
            if inspect.isawaitable(snapshot):
                snapshot = await snapshot
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Analysis database is unavailable.") from exc
        if snapshot is None:
            raise HTTPException(status_code=404, detail="Analysis task not found.")

        try:
            raw_progress = await run_in_threadpool(self.redis.get, f"analysis_progress:{task_id}")
            progress = json.loads(raw_progress) if raw_progress else None
        except Exception:
            progress = None
        md5 = snapshot.get("md5")
        reports = {}
        for tool in ("virustotal", "mobsf", "cape"):
            path = self.reports_dir / f"{tool}-{md5}.json" if md5 else None
            exists = bool(path and path.is_file())
            reports[tool] = {
                "exists": exists,
                "path": str(path) if path else None,
                "size": path.stat().st_size if exists else None,
            }
        return {
            "task_id": task_id,
            "database": snapshot,
            "progress": progress,
            "reports": reports,
        }
