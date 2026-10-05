from pydantic import BaseModel, ConfigDict, field_validator

MAX_FCM_TOKEN_LENGTH = 4096


class FcmTokenParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str
    fcm_token: str

    @field_validator("fcm_token")
    @classmethod
    def validate_fcm_token(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("ไม่พบ FCM token")
        if len(v) > MAX_FCM_TOKEN_LENGTH:
            raise ValueError("FCM token ยาวเกินกำหนด")
        return v


class FcmUnregisterParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str
