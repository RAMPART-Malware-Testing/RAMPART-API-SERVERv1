import re
from pydantic import BaseModel, field_validator, model_validator

ALLOWED_STATUSES    = {"pending", "processing", "success", "failed"}
MAX_SEARCH_LENGTH   = 100
MAX_LIMIT           = 100

class ReportsHistoryParams(BaseModel):
    page: int = 1
    limit: int = 10
    s: str | None = None
    status: str | None = None
    file_type: str | None = None
    # sort: 1 = asc, -1 = desc, 0 = no sort
    created_at: int = -1
    file_name: int = 0
    file_size: int = 0
    score: int = 0

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
        if v > MAX_LIMIT:
            raise ValueError(f"Limit must be <= {MAX_LIMIT}")
        return v

    @field_validator("s")
    @classmethod
    def validate_search(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        if len(v) > MAX_SEARCH_LENGTH:
            raise ValueError(f"Search query too long (max {MAX_SEARCH_LENGTH})")
        # Block SQL injection patterns
        dangerous = ["'", '"', ";", "--", "/*", "*/", "xp_", "exec", "drop", "union", "select", "insert", "update", "delete"]
        v_lower = v.lower()
        for pattern in dangerous:
            if pattern in v_lower:
                raise ValueError("Invalid search query")
        return v

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip().lower()
        if v not in ALLOWED_STATUSES:
            raise ValueError(f"status must be one of: {', '.join(ALLOWED_STATUSES)}")
        return v

    @field_validator("file_type")
    @classmethod
    def validate_file_type(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip().lower()
        if not re.fullmatch(r"[a-z0-9]{1,10}", v):
            raise ValueError("Invalid file_type format")
        return v

    @field_validator("created_at", "file_name", "file_size", "score")
    @classmethod
    def validate_sort_direction(cls, v: int) -> int:
        if v not in {-1, 0, 1}:
            raise ValueError("Sort direction must be -1, 0, or 1")
        return v

    @model_validator(mode="after")
    def validate_sort_conflict(self) -> "ReportsHistoryParams":
        # ป้องกันการ sort หลายคอลัมน์พร้อมกันเกิน 2
        active_sorts = sum(1 for v in [self.created_at, self.file_name, self.file_size, self.score] if v != 0)
        if active_sorts > 2:
            raise ValueError("Cannot sort by more than 2 columns simultaneously")
        return self