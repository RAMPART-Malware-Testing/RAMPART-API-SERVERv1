from pathlib import Path

from fastapi import APIRouter, Depends, Response
from fastapi.responses import HTMLResponse

from cores.async_pg_db import SessionLocal
from cores.redis import redis_client
from services.test_mode_service import TestModeService
from utils.test_mode import require_test_mode, test_identity


PAGE = Path(__file__).resolve().parent.parent / "templates" / "test_analysis.html"
router = APIRouter(prefix="/test", tags=["Test"], dependencies=[Depends(require_test_mode)])


def get_test_mode_service():
    username, email = test_identity()
    return TestModeService(SessionLocal, redis_client, username, email)


def user_data(user):
    return {
        "uid": str(user.uid),
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "status": user.status,
    }


@router.get("", response_class=HTMLResponse, include_in_schema=False)
async def console():
    return HTMLResponse(PAGE.read_text(encoding="utf-8"), headers={"Cache-Control": "no-store"})


@router.get("/api/status")
async def status(service: TestModeService = Depends(get_test_mode_service)):
    return await service.status()


@router.post("/api/user")
async def create_user(response: Response, service: TestModeService = Depends(get_test_mode_service)):
    state, user = await service.create_user()
    response.status_code = 201 if state == "created" else 200
    return {"state": state, "user": user_data(user)}


@router.post("/api/token")
async def create_token(service: TestModeService = Depends(get_test_mode_service)):
    return await service.issue_tokens()
