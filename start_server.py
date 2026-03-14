from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from utils.cypto.PasswordCreateAndVerify import get_password_hash
from utils.startup.create_root_user import create_root_user
from dotenv import load_dotenv
import uvicorn
load_dotenv()

app = FastAPI(
    title="RAMPART-AI",
    description="RAMPART-AI Models Testing",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    await create_root_user()
# ==========================================
# Endpoints
# ==========================================
from routers.auth import router as auth_router
from routers.analysis import router as analy_router
from routers.dashboar_route import router as dashboard_route

app.include_router(auth_router)
app.include_router(analy_router)
app.include_router(dashboard_route)

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
    x = get_password_hash("12345678aA!")
    print(x)
    return { "success": True, "message": "RAMPART-API is running" }

if __name__=="__main__":
    uvicorn.run("start_server:app", host="0.0.0.0", port=8006, reload=True)