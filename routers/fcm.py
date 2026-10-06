from fastapi import APIRouter

from controller.fcm_controller import (
    register_fcm_token_controller,
    unregister_fcm_token_controller,
)
from schemas.fcm import FcmTokenParams, FcmUnregisterParams

router = APIRouter(prefix="/api/fcm", tags=["FCM"])


@router.post("/register")
async def register_fcm_token(body: FcmTokenParams):
    return await register_fcm_token_controller(body)


@router.post("/unregister")
async def unregister_fcm_token(body: FcmUnregisterParams):
    return await unregister_fcm_token_controller(body)