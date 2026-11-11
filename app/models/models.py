import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Text, DateTime, ForeignKey, Integer, Float, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.database import Base

def uid() -> str:
    return str(uuid.uuid4())

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

class Investigation(Base):
    __tablename__ = "investigations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    targets: Mapped[list["Target"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")
    jobs: Mapped[list["CollectionJob"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")

class Target(Base):
    __tablename__ = "targets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    target_type: Mapped[str] = mapped_column(String(40), index=True)
    normalized_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    investigation: Mapped[Investigation] = relationship(back_populates="targets")

class CollectionJob(Base):
    __tablename__ = "collection_jobs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    modules: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(30), default="queued")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    investigation: Mapped[Investigation] = relationship(back_populates="jobs")

class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    target_id: Mapped[str | None] = mapped_column(ForeignKey("targets.id", ondelete="SET NULL"), nullable=True, index=True)
    job_id: Mapped[str | None] = mapped_column(ForeignKey("collection_jobs.id", ondelete="SET NULL"), nullable=True, index=True)
    module: Mapped[str] = mapped_column(String(50), index=True)
    finding_type: Mapped[str] = mapped_column(String(80))
    value: Mapped[str] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    verification_status: Mapped[str] = mapped_column(String(30), default="unverified")
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True)
    investigation: Mapped[Investigation] = relationship(back_populates="findings")

class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    target_id: Mapped[str | None] = mapped_column(ForeignKey("targets.id", ondelete="SET NULL"), nullable=True)
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_type: Mapped[str] = mapped_column(String(50), default="web_observation")
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    content_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    storage_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    collector_version: Mapped[str] = mapped_column(String(40), default="1.5.0")

class Entity(Base):
    __tablename__ = "entities"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    entity_type: Mapped[str] = mapped_column(String(50), index=True)
    value: Mapped[str] = mapped_column(String(2048), index=True)
    normalized_value: Mapped[str] = mapped_column(String(2048), index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

class Relationship(Base):
    __tablename__ = "relationships"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    source_entity_id: Mapped[str] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"))
    target_entity_id: Mapped[str] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"))
    relationship_type: Mapped[str] = mapped_column(String(80), default="related_to")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True)

class CredentialRecord(Base):
    __tablename__ = "credential_records"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    target_id: Mapped[str | None] = mapped_column(ForeignKey("targets.id", ondelete="SET NULL"), nullable=True)
    identifier_type: Mapped[str] = mapped_column(String(30), nullable=False)
    identifier_reference: Mapped[str] = mapped_column(String(512), nullable=False)
    encrypted_password: Mapped[str] = mapped_column(Text, nullable=False)
    authorization_context: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    last_accessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    investigation_id: Mapped[str | None] = mapped_column(ForeignKey("investigations.id", ondelete="SET NULL"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    object_type: Mapped[str] = mapped_column(String(50), nullable=False)
    object_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

class Source(Base):
    __tablename__ = "sources"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    category: Mapped[str] = mapped_column(String(60))
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="configured")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ExposureDataset(Base):
    __tablename__ = "exposure_datasets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    source_label: Mapped[str] = mapped_column(String(180), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_reference: Mapped[str | None] = mapped_column(Text, nullable=True)
    row_count: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class ExposureIndicator(Base):
    __tablename__ = "exposure_indicators"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    dataset_id: Mapped[str] = mapped_column(ForeignKey("exposure_datasets.id", ondelete="CASCADE"), index=True)
    indicator_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    identifier_hmac: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    masked_identifier: Mapped[str] = mapped_column(String(255), nullable=False)
    breach_name: Mapped[str | None] = mapped_column(String(180), nullable=True)
    breach_date: Mapped[str | None] = mapped_column(String(40), nullable=True)
    source_reference: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
