from sqlalchemy import Boolean, DateTime, ForeignKey, Numeric, Text, text, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from datetime import datetime
import uuid

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"

    uid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(String(20), server_default=text("'user'"))
    status: Mapped[str] = mapped_column(String(50), server_default=text("'active'"))
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.uid"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False
    )

    analyses = relationship("Analysis", foreign_keys="[Analysis.uid]", back_populates="user", cascade="all, delete-orphan")
    audit_logs_as_actor = relationship("AuditLog", foreign_keys="AuditLog.actor_uid", back_populates="actor")
    audit_logs_as_target = relationship("AuditLog", foreign_keys="AuditLog.target_uid", back_populates="target")

class Analysis(Base):
    __tablename__ = "analysis"

    aid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    uid: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.uid", ondelete="CASCADE"), nullable=False)
    rid: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("reports.rid", ondelete="SET NULL"), nullable=True)
    task_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    privacy: Mapped[bool] = mapped_column(Boolean, server_default=text("TRUE"))
    file_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    file_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    tools: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str | None] = mapped_column(Text, server_default=text("'pending'"))
    blocked_by: Mapped[str | None] = mapped_column(String(50), nullable=True)
    is_malicious: Mapped[bool | None] = mapped_column(Boolean, server_default=text("FALSE"))
    md5: Mapped[str | None] = mapped_column(Text, nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.uid"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP")
    )

    user = relationship("User", foreign_keys=[uid], back_populates="analyses")
    report = relationship("Reports", back_populates="analyses")

class Reports(Base):
    __tablename__ = "reports"

    rid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    file_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    virustotal_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    mobsf_score: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)
    cape_score: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)
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
    actor_uid: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.uid", ondelete="CASCADE"), nullable=False)
    target_uid: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.uid", ondelete="SET NULL"), nullable=True)
    action: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP")
    )

    actor = relationship("User", foreign_keys=[actor_uid], back_populates="audit_logs_as_actor")
    target = relationship("User", foreign_keys=[target_uid], back_populates="audit_logs_as_target")

from cores.async_pg_db import engine

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("✅ Database synced and tables created!")