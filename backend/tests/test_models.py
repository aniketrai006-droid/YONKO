"""
Tests for SQLAlchemy 2.x ORM models (backend/app/models.py).

Uses an in-memory SQLite engine so no PostgreSQL connection is required.
SQLite is dialect-compatible with all column types used in our models for
testing purposes (UUID stored as TEXT, DateTime as TEXT, etc.).

Security: these tests verify that audit_log_pg contains no PII columns,
which is a key steering rule requirement.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session

from app.models import (
    AuditLogPg,
    Base,
    Bundle,
    Document,
    FindingPg,
    UserPg,
)


# ---------------------------------------------------------------------------
# Shared fixture: in-memory SQLite engine with all tables created
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def engine():
    """Create an in-memory SQLite engine and build the schema once per module."""
    _engine = create_engine(
        "sqlite://",
        # SQLite needs this pragma to enforce FK constraints
        connect_args={"check_same_thread": False},
    )
    # Enable FK enforcement for SQLite
    with _engine.connect() as conn:
        conn.execute(text("PRAGMA foreign_keys = ON"))
        conn.commit()
    Base.metadata.create_all(_engine)
    yield _engine
    Base.metadata.drop_all(_engine)
    _engine.dispose()


@pytest.fixture
def db(engine):
    """Yield a session and roll back after each test for isolation."""
    session = Session(bind=engine)
    yield session
    session.rollback()
    session.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_all_tables_create(engine):
    """All seven expected tables must exist in the schema."""
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())
    expected = {
        "users_pg",
        "bundles",
        "documents",
        "findings_pg",
        "review_decisions",
        "audit_log_pg",
        "refresh_tokens",
    }
    assert expected == table_names, (
        f"Missing tables: {expected - table_names}; "
        f"Extra tables: {table_names - expected}"
    )


def test_users_pg_insert(db):
    """Insert a UserPg row and verify all fields round-trip correctly."""
    user_id = uuid.uuid4()
    user = UserPg(
        id=user_id,
        email="testuser@example.invalid",  # synthetic address, not a real person
        password_hash="$2b$12$fakehashfortest",
        role="reviewer",
        is_active=True,
    )
    db.add(user)
    db.flush()  # assign PK without committing

    result = db.get(UserPg, user_id)
    assert result is not None
    assert result.id == user_id
    assert result.email == "testuser@example.invalid"
    assert result.role == "reviewer"
    assert result.is_active is True
    assert result.password_hash == "$2b$12$fakehashfortest"


def test_bundle_cascade_delete(db):
    """
    Deleting a Bundle must cascade-delete its Documents and FindingsPg.

    Verifies that ON DELETE CASCADE FK constraints work end-to-end for
    the bundle → document and bundle → finding_pg relationships.
    """
    # Create a user (required for bundle FK)
    user = UserPg(
        email="cascade-test@example.invalid",
        password_hash="$2b$12$fakehash",
        role="reviewer",
    )
    db.add(user)
    db.flush()

    # Create a bundle owned by the user
    bundle = Bundle(
        owner_email=user.email,
        bundle_ref="tmp-cascade-test-dir",
    )
    db.add(bundle)
    db.flush()

    # Add a document to the bundle
    doc = Document(
        bundle_id=bundle.id,
        filename="aadhaar_synthetic.pdf",
        document_type="aadhaar",
        page_count=1,
    )
    db.add(doc)

    # Add a finding to the bundle
    finding = FindingPg(
        bundle_id=bundle.id,
        field="name",
        decision="contradiction",
        severity="high",
        reason="Name mismatch between documents",
    )
    db.add(finding)
    db.flush()

    doc_id = doc.id
    finding_id = finding.id
    bundle_id = bundle.id

    # Delete the bundle — cascade should remove document and finding
    db.delete(bundle)
    db.flush()

    # Both child records should be gone
    assert db.get(Document, doc_id) is None, "Document should be cascade-deleted"
    assert db.get(FindingPg, finding_id) is None, "Finding should be cascade-deleted"
    assert db.get(Bundle, bundle_id) is None, "Bundle should be deleted"


def test_audit_log_has_no_pii_columns(engine):
    """
    audit_log_pg must contain no column named after PII fields.

    This directly tests the steering rule: 'Log security events to the
    audit log, never log PII or tokens.' The forbidden column names are
    those explicitly listed in FEAT-002 and the steering file.
    """
    inspector = inspect(engine)
    column_names = {col["name"] for col in inspector.get_columns("audit_log_pg")}

    # These column names are FORBIDDEN in audit_log_pg
    pii_column_names = {"email", "name", "dob", "aadhaar", "pan"}

    found_pii = column_names & pii_column_names
    assert not found_pii, (
        f"audit_log_pg contains PII column(s): {found_pii}. "
        "Remove them and use actor_id (opaque identifier) instead."
    )


def test_persist_results_flag_default():
    """
    settings.PERSIST_RESULTS must default to False.

    This ensures the /analyze endpoint does not write to the database
    unless the operator explicitly opts in via the environment variable.
    Preventing accidental writes is a security and data-integrity concern.
    """
    from app.config import settings

    assert settings.PERSIST_RESULTS is False, (
        "PERSIST_RESULTS must default to False to keep analysis stateless "
        "unless explicitly enabled by the operator."
    )
