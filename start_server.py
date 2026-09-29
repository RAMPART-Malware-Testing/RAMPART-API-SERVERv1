import logging
import logging.handlers
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from starlette.middleware.sessions import SessionMiddleware
from cores.Schema.schema_class import init_db
from dotenv import load_dotenv
import uvicorn

load_dotenv()

LOG_DIR = Path(os.getenv("SERVER_LOG_DIR") or (Path.home() / "rampart-logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "server.log"

def _configure_file_logging() -> None:
    handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    handler.setLevel(logging.WARNING)
    logging.getLogger("watchfiles").setLevel(logging.WARNING)
    logging.getLogger().setLevel(logging.INFO)
    for name in ("", "uvicorn", "uvicorn.error", "uvicorn.access", "rampart"):
        logging.getLogger(name).addHandler(handler)

_configure_file_logging()

app = FastAPI(
    title="RAMPART",
    description="RAMPART",
    version="1.0.0"
)

_FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000").rstrip("/")
_ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", _FRONTEND_URL).split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", os.getenv("JWT_SECRET", "")),
    same_site="lax",
    https_only=os.getenv("SESSION_COOKIE_HTTPS_ONLY", "FALSE").upper() == "TRUE",
)

@app.on_event("startup")
async def startup_event():
    await init_db()
    from services.admin.root_bootstrap import ensure_root_master_account
    await ensure_root_master_account()

from routers.auth import router as auth_router
from routers.profile import router as profile_router
from routers.analysis import router as analy_router
from routers.test_route import router as test_router
from utils.test_mode import test_mode_enabled
from routers.dashboar_route import router as dashboard_route
from routers.admin import router as admin_router

app.include_router(analy_router)
app.include_router(test_router, include_in_schema=test_mode_enabled())
app.include_router(auth_router)
app.include_router(profile_router)
app.include_router(dashboard_route)
app.include_router(admin_router)

from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    errors = []
    for error in exc.errors():
        errors.append({
            "type": error.get("type"),
            "loc":  list(error.get("loc", [])),
            "msg":  error.get("msg"),
            "input": error.get("input"),
        })
    print("=== 422 DETAIL ===", errors)
    return JSONResponse(status_code=422, content={"detail": errors})

@app.get('/')
async def root():
    return { "success": True, "message": "RAMPART-API is running" }

@app.get('/scan')
async def scan_page():
    return FileResponse('scan.html')

RELOAD_EXCLUDES = [
    "temps_files/*",
    "reports/*",
    "results/*",
    "avatars/*",
    "logs/*",
    "*.log",
]

if __name__=="__main__":
    uvicorn.run(
        "start_server:app",
        host="0.0.0.0",
        port=8006,
        reload=True,
        reload_excludes=RELOAD_EXCLUDES,
    )
