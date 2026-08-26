from fastapi import HTTPException
from cores.async_pg_db import SessionLocal
from schemas.dashboard import ReportsHistoryParams
from services.admin.authz import AuthError, ensure_not_banned, get_current_user
from services.dashboard.dashboars_service import get_dashboard_summary, get_recent_activities, get_reports_history
from services.token_service import TokenService
from pydantic import BaseModel
from utils.uuid import parse_uuid

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
            return await get_dashboard_summary(session, user.uid, user.role)
        except Exception:
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
            raise HTTPException(status_code=500, detail="Internal server error")
        
async def reports_history_controller(body: ReportsHistoryParams):
    async with SessionLocal() as session:
        try:
            return await get_reports_history(session, body)
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=500, detail="Internal server error")

