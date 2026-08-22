from pydantic import BaseModel, field_validator


class ProfileTokenParams(BaseModel):
    token: str


class UpdateProfileParams(BaseModel):
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
        if not (3 <= len(v) <= 50):
            raise ValueError("Username must be between 3 and 50 characters")
        return v
