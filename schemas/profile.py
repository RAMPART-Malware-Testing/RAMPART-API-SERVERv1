import re

from pydantic import BaseModel, ConfigDict, field_validator

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.\-\u0E00-\u0E7F]{3,50}$")

class ProfileTokenParams(BaseModel):
    token: str

class DownloadRecordParams(BaseModel):
    token: str
    file_name: str | None = None
    tool: str | None = None
    md5: str | None = None

class UpdateProfileParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str
    username: str | None = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        if not _USERNAME_RE.match(v):
            raise ValueError(
                "ชื่อผู้ใช้ต้องมีความยาว 3-50 ตัวอักษร "
                "และใช้ได้เฉพาะตัวอักษรไทย ตัวอักษรอังกฤษ ตัวเลข '.', '_' และ '-' เท่านั้น"
            )
        return v
