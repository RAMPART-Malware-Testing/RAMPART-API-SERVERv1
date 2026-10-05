from fastapi import APIRouter

from controller.fcm_controller import (
    register_fcm_token_controller,
    unregister_fcm_token_controller,
)
from schemas.fcm import FcmTokenParams, FcmUnregisterParams

router = APIRouter(prefix="/api/fcm", tags=["FCM"])


@router.post("/register")
async def register_fcm_token(body: FcmTokenParams):
    """Store the device's FCM token on the user row.

    The token is written to `users.fcm_token` — one token per account, so a
    second device replaces the first rather than joining it.
    """
    return await register_fcm_token_controller(body)


@router.post("/unregister")
async def unregister_fcm_token(body: FcmUnregisterParams):
    """Forget this device's token on sign-out."""
    return await unregister_fcm_token_controller(body)