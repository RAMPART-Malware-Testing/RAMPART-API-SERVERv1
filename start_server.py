import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from starlette.middleware.sessions import SessionMiddleware
from cores.Schema.schema_class import init_db
from dotenv import load_dotenv
import uvicorn

load_dotenv()

app = FastAPI(
    title="RAMPART",
    description="RAMPART",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Required by Authlib's OAuth client to stash the CSRF `state`/`nonce`
# between the /login redirect and the /callback request.
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", os.getenv("JWT_SECRET", "")),
    same_site="lax",
    https_only=os.getenv("SESSION_COOKIE_HTTPS_ONLY", "FALSE").upper() == "TRUE",
)


@app.on_event("startup")
async def startup_event():
    await init_db()
    # No pre-seeded admin account anymore: whoever signs in via Google/GitHub
    # with an e-mail matching ROOT_EMAIL (.env) is auto-promoted to admin on
    # login - see services/oauth/oauth_service.find_or_create_user.
    
from routers.auth import router as auth_router
from routers.profile import router as profile_router
from routers.analysis import router as analy_router
from routers.test_route import router as test_router
from utils.test_mode import test_mode_enabled
from routers.dashboar_route import router as dashboard_route
from routers.test_route import router as test_router

app.include_router(analy_router)
app.include_router(test_router, include_in_schema=test_mode_enabled())
app.include_router(auth_router)
app.include_router(profile_router)
app.include_router(dashboard_route)
app.include_router(test_router)

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

if __name__=="__main__":
    uvicorn.run("start_server:app", host="0.0.0.0", port=8006, reload=True)
