"""
SQLAlchemy 2.x ORM models for the YONKO PostgreSQL database.

Uses SQLAlchemy 2.x Mapped / mapped_column syntax exclusively — no legacy Column.
All primary keys are UUID with Python-side uuid4() defaults (no server_default for PKs).

Security: This module defines the schema only. No credentials, secrets, or PII
are present here. See app.config for configuration and app.database for the
session factory.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Shared declarative base for all YONKO PostgreSQL models."""
    pass


class UserPg(Base):
    """
    Reviewer / operator accounts.

    Security: password_hash stores only a bcrypt hash, never the plaintext
    password. The role column is restricted to known values ('reviewer',
    'admin') by application logic and tested via 403 checks.
    """
    __tablename__ = "users_pg"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="reviewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now()
    )

    # Relationships
    bundles: Mapped[list["Bundle"]] = relationship(
        "Bundle", back_populates="owner", cascade="all, delete-orphan"
    )


class Bundle(Base):
    """
    A group of documents submitted together for contradiction analysis.

    bundle_ref stores the temporary directory name for diagnostic traceability
    only — it is NOT a file path and must not be used to reconstruct file access.
    """
    __tablename__ = "bundles"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    # FK to users_pg.email (not users_pg.id) per spec — allows lookup by email
    owner_email: Mapped[str] = mapped_column(
        String(255),
        ForeignKey("users_pg.email", ondelete="CASCADE"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now()
    )
    # Temp dir name for diagnostics only — no filesystem reconstruction possible
    bundle_ref: Mapped[str] = mapped_column(Text, nullable=False)

    # Relationships
    owner: Mapped["UserPg"] = relationship("UserPg", back_populates="bundles")
    documents: Mapped[list["Document"]] = relationship(
        "Document", back_populates="bundle", cascade="all, delete-orphan"
    )
    findings: Mapped[list["FindingPg"]] = relationship(
        "FindingPg", back_populates="bundle", cascade="all, delete-orphan"
    )


class Document(Base):
    """
    Metadata for a document within a bundle. No file bytes are stored here.

    Security: only metadata (filename, type, page count) is persisted.
    Actual file content is never written to this table.
    """
    __tablename__ = "documents"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    bundle_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bundles.id", ondelete="CASCADE"), nullable=False
    )
    filename: Mapped[str] = mapped_column(Text, nullable=False)
    document_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    page_count: Mapped[int] = mapped_column(Integer, default=1)

    # Relationships
    bundle: Mapped["Bundle"] = relationship("Bundle", back_populates="documents")


class FindingPg(Base):
    """
    A single contradiction finding produced by the detection engine.

    field / decision / severity semantics are fixed by docs/API_CONTRACT.md.
    Do not change these column types or defaults — they must stay in sync
    with the /analyze response contract.
    """
    __tablename__ = "findings_pg"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    bundle_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bundles.id", ondelete="CASCADE"), nullable=False
    )
    field: Mapped[str] = mapped_column(String(255), nullable=False)
    decision: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    similarity: Mapped[float | None] = mapped_column(Float, nullable=True)
    recommended_action: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    bundle: Mapped["Bundle"] = relationship("Bundle", back_populates="findings")
    review_decisions: Mapped[list["ReviewDecision"]] = relationship(
        "ReviewDecision", back_populates="finding", cascade="all, delete-orphan"
    )


class ReviewDecision(Base):
    """
    A human reviewer's accept/reject decision on a finding.
    """
    __tablename__ = "review_decisions"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings_pg.id", ondelete="CASCADE"), nullable=False
    )
    reviewer_email: Mapped[str] = mapped_column(String(255), nullable=False)
    decision: Mapped[str] = mapped_column(String(50), nullable=False)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now()
    )

    # Relationships
    finding: Mapped["FindingPg"] = relationship(
        "FindingPg", back_populates="review_decisions"
    )


# Security: no PII stored in audit_log_pg. actor_id is an opaque identifier.
class AuditLogPg(Base):
    """
    Immutable security audit trail for the PostgreSQL-backed application.

    Security: This table intentionally has NO columns named 'email', 'name',
    'dob', 'aadhaar', 'pan', or any other PII field. actor_id is an opaque
    string (e.g. a UUID or hashed identifier) — never a raw email address or
    personal identifier. This design satisfies Rule 7 of the steering file:
    'Log security events to the audit log, never log PII or tokens.'
    """
    __tablename__ = "audit_log_pg"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    ts: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    # Opaque actor identifier — never store raw email or name here.
    # Use a UUID, hashed value, or role token to identify who performed the action.
    actor_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    outcome: Mapped[str | None] = mapped_column(String(50), nullable=True)
