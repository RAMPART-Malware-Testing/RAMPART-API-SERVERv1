import re

from pydantic import BaseModel, ConfigDict, field_validator

# Allowlist rather than a denylist (OWASP A03 - Injection / stored-XSS
# defense in depth): usernames are rendered as-is in the frontend (Navbar,
# profile page) without any HTML-escaping guarantee from this layer, so
# accepting arbitrary Unicode/control characters here would push the whole
# burden of safe rendering onto every future UI that ever displays a
# username. Restricting to a known-safe charset closes that off at the
# source instead. Thai script (U+0E00-U+0E7F) is allowlisted alongside
# Latin letters/digits since usernames may be written in Thai.
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
