from fastapi import HTTPException
from cores.async_pg_db import SessionLocal
from services.dashboard.dashboars_service import get_dashboard_summary, get_recent_activities
from services.token_service import TokenService
from pydantic import BaseModel

class DashboardParams(BaseModel):
    token: str

async def dashboard_summary_controller(body: DashboardParams):
    payload, err = TokenService.verify_token(body.token, "access")
    if err:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    uid  = payload.get("sub")
    role = payload.get("role", "user")
    if not uid:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    try:
        uid = int(uid)
    except (ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid token payload")

    async with SessionLocal() as session:
        try:
            return await get_dashboard_summary(session, uid, role)
        except Exception:
            raise HTTPException(status_code=500, detail="Internal server error")


async def recent_activities_controller(body: DashboardParams):
    payload, err = TokenService.verify_token(body.token, "access")
    if err:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    uid  = payload.get("sub")
    role = payload.get("role", "user")
    if not uid:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    try:
        uid = int(uid)
    except (ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid token payload")

    async with SessionLocal() as session:
        try:
            return await get_recent_activities(session, uid, role)
        except Exception:
            raise HTTPException(status_code=500, detail="Internal server error")