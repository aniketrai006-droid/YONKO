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
    Reviewer / operator / citizen accounts for the JWT auth system.

    Security: password_hash stores only an Argon2id hash, never the plaintext
    password. The role column is restricted to known values ('citizen',
    'reviewer', 'admin') by application logic and tested via 403 checks.
    totp_secret holds an AES-GCM-encrypted TOTP shared secret (see
    app.security_helpers.encrypt_field) — never plaintext.
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
    # Encrypted TOTP secret; NULL until the user enrols in MFA.
    totp_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Brute-force lockout state.
    failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Relationships
    # Two FKs point at users_pg (owner_email and assigned_reviewer_id), so
    # the join must be pinned to owner_email explicitly.
    bundles: Mapped[list["Bundle"]] = relationship(
        "Bundle",
        back_populates="owner",
        cascade="all, delete-orphan",
        primaryjoin="UserPg.email == foreign(Bundle.owner_email)",
    )
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        "RefreshToken", back_populates="user", cascade="all, delete-orphan"
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
    # UUID ownership pointer — the authoritative owner for PostgreSQL
    # Row-Level Security (citizen policy: owner_id = app.current_user_id).
    # owner_email is kept for the SQLite dashboard and FK compatibility.
    owner_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users_pg.id", ondelete="SET NULL"), nullable=True
    )
    # Reviewer assigned to this bundle. NULL = unassigned; only this reviewer
    # (or an admin) may record decisions on the bundle's findings.
    assigned_reviewer_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users_pg.id", ondelete="SET NULL"), nullable=True
    )

    # Relationships
    # Pinned to owner_email because assigned_reviewer_id is a second FK to
    # users_pg (see UserPg.bundles). foreign() marks the Bundle side.
    owner: Mapped["UserPg"] = relationship(
        "UserPg",
        back_populates="bundles",
        primaryjoin="foreign(Bundle.owner_email) == UserPg.email",
    )
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

    # Data-minimization columns — Rule 2 of the steering file.
    # masked_value: last-4 representation of the primary identity field (if present).
    # id_hash: HMAC-SHA256 of the raw identity value — for cross-document matching.
    # Neither stores the raw identity number.
    masked_value: Mapped[str | None] = mapped_column(String(20), nullable=True)
    id_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # PERSIST_UPLOADS columns — populated only when PERSIST_UPLOADS=True.
    # file_hash: hex SHA-256 of the original file bytes.
    # storage_key: MinIO object key. File bytes never enter this table.
    file_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    storage_key: Mapped[str | None] = mapped_column(Text, nullable=True)

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
    # Opaque reviewer UUID (users_pg.id) — the authoritative attribution.
    reviewer_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users_pg.id", ondelete="SET NULL"), nullable=True
    )
    # Kept for display/back-compat with the case dashboard.
    reviewer_email: Mapped[str] = mapped_column(String(255), nullable=False)
    decision: Mapped[str] = mapped_column(String(50), nullable=False)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now()
    )

    # Relationships
    finding: Mapped["FindingPg"] = relationship(
        "FindingPg", back_populates="review_decisions"
    )


class RefreshToken(Base):
    """
    Server-side record of issued refresh tokens (JWT auth system).

    Security: only the SHA-256 hash of the token is stored — the raw token
    exists solely in the client's possession. Rotation marks the old row
    used=True and issues a new row in the same family. Presenting an already
    used or revoked token is treated as theft and revokes the entire family
    (OAuth 2.1 BCP, RFC 9700 §4.14.2).
    """
    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users_pg.id", ondelete="CASCADE"), nullable=False
    )
    # SHA-256 hex digest of the refresh JWT.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    # All tokens descended from one login share a family id; reuse of an old
    # token revokes every outstanding token in the family.
    family_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("refresh_tokens.id", ondelete="CASCADE"), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now()
    )

    # Relationships
    user: Mapped["UserPg"] = relationship("UserPg", back_populates="refresh_tokens")


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
