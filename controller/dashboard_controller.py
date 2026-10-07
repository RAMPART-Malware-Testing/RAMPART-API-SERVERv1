import logging

from fastapi import HTTPException
from cores.async_pg_db import SessionLocal
from schemas.dashboard import ReportsHistoryParams
from services.admin.authz import AuthError, ensure_not_banned, get_current_user
from services.dashboard.dashboars_service import get_dashboard_summary_service, get_recent_activities, get_reports_history
from services.token_service import TokenService
from pydantic import BaseModel
from utils.uuid import parse_uuid

logger = logging.getLogger("rampart.dashboard")

class DashboardParams(BaseModel):
    token: str

async def dashboard_summary_controller(body: DashboardParams):
    async with SessionLocal() as session:
        try:
            user = await get_current_user(session, body.token)
            ensure_not_banned(user)
        except AuthError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message)

        try:
            return await get_dashboard_summary_service(session, user.uid, user.role)
        except Exception:
            logger.exception("dashboard summary failed uid=%s role=%s", user.uid, user.role)
            raise HTTPException(status_code=500, detail="Internal server error")

async def recent_activities_controller(body: DashboardParams):
    async with SessionLocal() as session:
        try:
            user = await get_current_user(session, body.token)
            ensure_not_banned(user)
        except AuthError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message)

        try:
            return await get_recent_activities(session, user.uid, user.role)
        except Exception:
            logger.exception("recent activities failed uid=%s role=%s", user.uid, user.role)
            raise HTTPException(status_code=500, detail="Internal server error")
        
async def reports_history_controller(body: ReportsHistoryParams):
    async with SessionLocal() as session:
        try:
            user = await get_current_user(session, body.token)
            ensure_not_banned(user)
        except AuthError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message)

        try:
            return await get_reports_history(session, body)
        except HTTPException:
            raise
        except Exception:
            logger.exception("reports history failed uid=%s", user.uid)
            raise HTTPException(status_code=500, detail="Internal server error")

