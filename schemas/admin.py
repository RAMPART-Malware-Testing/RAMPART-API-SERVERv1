import re

from pydantic import BaseModel, ConfigDict, field_validator

from services.admin.authz import ASSIGNABLE_ROLES

MAX_SEARCH_LENGTH = 100
MAX_LIMIT = 100
MAX_REASON_LENGTH = 500

_DANGEROUS_SQL_PATTERNS = [
    "'", '"', ";", "--", "/*", "*/", "xp_", "exec", "drop", "union",
    "select", "insert", "update", "delete",
]


def _validate_search_text(v: str | None) -> str | None:
    if v is None:
        return None
    v = v.strip()
    if not v:
        return None
    if len(v) > MAX_SEARCH_LENGTH:
        raise ValueError(f"Search query too long (max {MAX_SEARCH_LENGTH})")
    v_lower = v.lower()
    for pattern in _DANGEROUS_SQL_PATTERNS:
        if pattern in v_lower:
            raise ValueError("Invalid search query")
    return v


class AdminTokenParams(BaseModel):
    """Base shape shared by every admin-panel request: just the caller's
    own access token. Every admin controller resolves `actor` from this
    token via services.admin.authz.get_current_user - never from a target
    uid supplied by the client."""

    model_config = ConfigDict(extra="forbid")

    token: str


class AdminListUsersParams(AdminTokenParams):
    page: int = 1
    limit: int = 20
    q: str | None = None
    role: str | list[str] | None = None
    banned: bool | None = None

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

    @field_validator("q")
    @classmethod
    def validate_q(cls, v: str | None) -> str | None:
        return _validate_search_text(v)

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str | list[str] | None) -> str | list[str] | None:
        if v is None:
            return None
        allowed = {"user", "admin", "master"}
        if isinstance(v, str):
            v = v.strip().lower()
            if v not in allowed:
                raise ValueError("role must be one of: user, admin, master")
            return v
        cleaned = [r.strip().lower() for r in v]
        for r in cleaned:
            if r not in allowed:
                raise ValueError("role must be one of: user, admin, master")
        return cleaned


class AdminTargetUserParams(AdminTokenParams):
    target_uid: str


class AdminUserHistoryParams(AdminTargetUserParams):
    page: int = 1
    limit: int = 10
    s: str | None = None
    status: str | None = None
    file_type: str | None = None
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
    def validate_s(cls, v: str | None) -> str | None:
        return _validate_search_text(v)

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip().lower()
        if v not in {"pending", "processing", "success", "failed"}:
            raise ValueError("Invalid status")
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


class AdminBanUserParams(AdminTargetUserParams):
    reason: str

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("A ban reason is required")
        if len(v) > MAX_REASON_LENGTH:
            raise ValueError(f"Reason too long (max {MAX_REASON_LENGTH})")
        return v


class AdminUnbanUserParams(AdminTargetUserParams):
    pass


class AdminChangeRoleParams(AdminTargetUserParams):
    new_role: str

    @field_validator("new_role")
    @classmethod
    def validate_new_role(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if v not in ASSIGNABLE_ROLES:
            raise ValueError(
                f"new_role must be one of: {', '.join(sorted(ASSIGNABLE_ROLES))}"
            )
        return v


class AdminAuditLogParams(AdminTokenParams):
    page: int = 1
    limit: int = 20
    actor_uid: str | None = None
    action: str | None = None

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

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str | None) -> str | None:
        return _validate_search_text(v)


ALLOWED_ANALYSIS_STATUSES = {"pending", "processing", "success", "failed"}
ALLOWED_RISK_LEVELS = {"Low", "Caution", "High", "Critical"}


class AdminListFilesParams(AdminTokenParams):
    page: int = 1
    limit: int = 20
    q: str | None = None
    status: str | None = None
    file_type: str | None = None
    privacy: bool | None = None

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

    @field_validator("q")
    @classmethod
    def validate_q(cls, v: str | None) -> str | None:
        return _validate_search_text(v)

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip().lower()
        if v not in ALLOWED_ANALYSIS_STATUSES:
            raise ValueError(f"status must be one of: {', '.join(ALLOWED_ANALYSIS_STATUSES)}")
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


class AdminDeleteFileParams(AdminTokenParams):
    aid: str
    reason: str

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("A deletion reason is required")
        if len(v) > MAX_REASON_LENGTH:
            raise ValueError(f"Reason too long (max {MAX_REASON_LENGTH})")
        return v


class AdminListReportsParams(AdminTokenParams):
    page: int = 1
    limit: int = 20
    q: str | None = None
    risk_level: str | None = None
    file_type: str | None = None

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

    @field_validator("q")
    @classmethod
    def validate_q(cls, v: str | None) -> str | None:
        return _validate_search_text(v)

    @field_validator("risk_level")
    @classmethod
    def validate_risk_level(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if v not in ALLOWED_RISK_LEVELS:
            raise ValueError(f"risk_level must be one of: {', '.join(sorted(ALLOWED_RISK_LEVELS))}")
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
