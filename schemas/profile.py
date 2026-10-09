import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.\-\u0E00-\u0E7F]{3,50}$")
_PASSWORD_MIN_LENGTH = 8
_PASSWORD_UPPER_RE = re.compile(r"[A-Z]")
_PASSWORD_LOWER_RE = re.compile(r"[a-z]")
_PASSWORD_DIGIT_RE = re.compile(r"[0-9]")
_PASSWORD_SPECIAL_RE = re.compile(r"[!@#$%^&*(),.?\":{}|<>]")

MAX_PASSWORD_LENGTH = 128

class ProfileTokenParams(BaseModel):
    token: str

HISTORY_DEFAULT_LIMIT = 25
HISTORY_MAX_LIMIT = 100

class HistoryPageParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str
    page: int = 1
    limit: int = HISTORY_DEFAULT_LIMIT

    @field_validator("page")
    @classmethod
    def validate_page(cls, v: int) -> int:
        if v < 1:
            raise ValueError("Page must be >= 1")
        if v > 10_000:
            raise ValueError("Page too large")
        return v

    @field_validator("limit")
    @classmethod
    def validate_limit(cls, v: int) -> int:
        if v < 1:
            raise ValueError("Limit must be >= 1")
        if v > HISTORY_MAX_LIMIT:
            raise ValueError(f"Limit must be <= {HISTORY_MAX_LIMIT}")
        return v

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

class ChangePasswordParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str
    currentPasswd: str
    newPasswd: str

    @field_validator("currentPasswd")
    @classmethod
    def validate_current_password(cls, v: str) -> str:
        if not v:
            raise ValueError("กรุณากรอกรหัสผ่านปัจจุบัน")
        return v

    @field_validator("newPasswd")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        if len(v) < _PASSWORD_MIN_LENGTH:
            raise ValueError(f"รหัสผ่านต้องมีความยาวอย่างน้อย {_PASSWORD_MIN_LENGTH} ตัวอักษร")
        if len(v) > MAX_PASSWORD_LENGTH:
            raise ValueError(f"รหัสผ่านต้องยาวไม่เกิน {MAX_PASSWORD_LENGTH} ตัวอักษร")
        if not _PASSWORD_UPPER_RE.search(v):
            raise ValueError("รหัสผ่านต้องมีตัวอักษรพิมพ์ใหญ่อย่างน้อย 1 ตัว")
        if not _PASSWORD_LOWER_RE.search(v):
            raise ValueError("รหัสผ่านต้องมีตัวอักษรพิมพ์เล็กอย่างน้อย 1 ตัว")
        if not _PASSWORD_DIGIT_RE.search(v):
            raise ValueError("รหัสผ่านต้องมีตัวเลขอย่างน้อย 1 ตัว")
        if not _PASSWORD_SPECIAL_RE.search(v):
            raise ValueError("รหัสผ่านต้องมีอักขระพิเศษอย่างน้อย 1 ตัว")
        return v

class NotificationCountsParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str
    reports_since: datetime | None = None
    public_since: datetime | None = None
