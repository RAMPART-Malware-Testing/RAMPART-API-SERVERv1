from sqlalchemy import Boolean, DateTime, ForeignKey, Numeric, Text, text, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from datetime import datetime, timezone
import uuid

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"

    uid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    avatar_url: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    role: Mapped[str] = mapped_column(String(20), server_default=text("'user'"))
    status: Mapped[str] = mapped_column(String(50), server_default=text("'active'"))
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.uid"), nullable=True)
    fcm_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Ban state. This is the source of truth for access control - `status`
    # above is legacy free-text and is NOT authoritative for authorization
    # decisions. Master accounts can never have is_banned=True (enforced at
    # the service layer in services/admin/authz.py, not by a DB constraint).
    is_banned: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("FALSE"))
    banned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    banned_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    banned_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.uid"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    oauth_accounts = relationship("OAuthAccount", back_populates="user", cascade="all, delete-orphan")
    analyses = relationship("Analysis", foreign_keys="[Analysis.uid]", back_populates="user", cascade="all, delete-orphan")
    audit_logs_as_actor = relationship("AuditLog", foreign_keys="AuditLog.actor_uid", back_populates="actor")
    audit_logs_as_target = relationship("AuditLog", foreign_keys="AuditLog.target_uid", back_populates="target")


class OAuthAccount(Base):
    """Links a user to one external OAuth identity (Google or GitHub).

    A repeat login is resolved to the *same* uid by looking this table up
    on (provider, provider_uid) - that pair is what the provider guarantees
    is stable and unique for a given external account.
    """
    __tablename__ = "oauth_accounts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    uid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.uid", ondelete="CASCADE"), nullable=False)
    provider: Mapped[str] = mapped_column(String(20), nullable=False)
    provider_uid: Mapped[str] = mapped_column(String(255), nullable=False)
    provider_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP")
    )

    user = relationship("User", back_populates="oauth_accounts")

class Analysis(Base):
    __tablename__ = "analysis"

    aid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    uid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.uid", ondelete="CASCADE"), nullable=False)
    rid: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("reports.rid", ondelete="SET NULL"), nullable=True)
    task_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    privacy: Mapped[bool] = mapped_column(Boolean, server_default=text("TRUE"))
    file_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    file_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    tools: Mapped[str | None] = mapped_column(Text, nullable=True)
    # JSON-encoded dict of {tool_name: reason} for any tool that was force-
    # skipped after exhausting its error/rate-limit retry budget (see
    # bgProcessing/tasks.py). NULL when every attempted tool either
    # succeeded outright or was skipped because the file type is simply
    # unsupported by that tool - this column is never populated for that
    # case, only for the retry-exhausted case.
    tool_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str | None] = mapped_column(Text, server_default=text("'pending'"))
    blocked_by: Mapped[str | None] = mapped_column(String(50), nullable=True)
    is_malicious: Mapped[bool | None] = mapped_column(Boolean, server_default=text("FALSE"))
    md5: Mapped[str | None] = mapped_column(Text, nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.uid"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP")
    )

    user = relationship("User", foreign_keys=[uid], back_populates="analyses")
    report = relationship("Reports", back_populates="analyses")

class Reports(Base):
    __tablename__ = "reports"

    rid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    package: Mapped[str | None] = mapped_column(Text, nullable=True)
    type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    score: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(128), nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    analysis_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_indicators: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    file_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    virustotal_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    mobsf_score: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)
    cape_score: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)
    # RampartAI full /predict response (malware_probability, benign_probability,
    # prediction, confidence, ...) stored verbatim as JSON.
    rampart_ai_score: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    rampart_score: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)
    gemini_recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    malware_signatures: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP")
    )

    analyses = relationship("Analysis", foreign_keys="[Analysis.rid]", back_populates="report")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    log_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    actor_uid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.uid", ondelete="CASCADE"), nullable=False)
    target_uid: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.uid", ondelete="SET NULL"), nullable=True)
    action: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP")
    )

    actor = relationship("User", foreign_keys=[actor_uid], back_populates="audit_logs_as_actor")
    target = relationship("User", foreign_keys=[target_uid], back_populates="audit_logs_as_target")


class LoginHistory(Base):
    __tablename__ = "login_history"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    uid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.uid", ondelete="CASCADE"), nullable=False)
    provider: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP")
    )


class DownloadHistory(Base):
    __tablename__ = "download_history"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    uid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.uid", ondelete="CASCADE"), nullable=False)
    file_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    tool: Mapped[str | None] = mapped_column(String(32), nullable=True)
    md5: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP")
    )

from cores.async_pg_db import engine

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("[OK] Database synced and tables created!")
