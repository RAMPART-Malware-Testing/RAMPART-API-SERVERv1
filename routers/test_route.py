from fastapi import APIRouter
from services.fcm_service import FCMService

router = APIRouter(tags=["Test"])


@router.get("/test/w1")
async def test_notification(
    fcm_token: str,
    title: str = "RAMPART Test",
    body: str = "การทดสอบการแจ้งเตือนสำเร็จ",
):
    result = await FCMService.send_notification(
        token=fcm_token,
        title=title,
        body=body,
        data={"type": "test", "source": "w1"},
    )
    return result
