from fastapi import APIRouter

from controller.dashboard_controller import DashboardParams, dashboard_summary_controller, recent_activities_controller, reports_history_controller
from schemas.dashboard import ReportsHistoryParams

router = APIRouter(prefix="/api/analy/v1/dashboard", tags=["Dashboard"])

@router.post("/reports")
async def get_reports_summary(body: ReportsHistoryParams):
    return await reports_history_controller(body)

@router.post("/summary")
async def get_dashboard_summary(body: DashboardParams):
    return await dashboard_summary_controller(body)

@router.post("/recent-activities")
async def get_recent_activities(body: DashboardParams):
    return await recent_activities_controller(body)