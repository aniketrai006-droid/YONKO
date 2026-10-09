"""
Tests for PERSIST_RESULTS integration in POST /analyze.

These tests verify three behaviours:
  1. When PERSIST_RESULTS=False (default) no DB rows are written.
  2. When PERSIST_RESULTS=True a Bundle row is created after a successful analysis.
  3. A DB failure in _persist_bundle does NOT cause /analyze to return non-200.

All tests monkeypatch detect_bundle to return a synthetic BundleDetectionResult
so no real images, OCR, or Tesseract installation are required.

Security: no PII is used in any fixture or assertion.  Synthetic values only.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

from app.detect.types import BundleDetectionResult, FieldEvidence, Finding
from app.main import app
from app.models import Base, Bundle

# ---------------------------------------------------------------------------
# Shared synthetic BundleDetectionResult (no real images or OCR needed)
# ---------------------------------------------------------------------------

FAKE_RESULT = BundleDetectionResult(
    bundle_path="/tmp/fake-bundle",
    documents_processed=2,
    findings=[
        Finding(
            field="name",
            decision="conflict",
            severity="HIGH",
            reason="Name differs between documents (synthetic test data).",
            similarity=0.42,
            recommended_action="Review manually.",
            evidence=[
                FieldEvidence(
                    document_type="id_card",
                    source_path="/tmp/fake-bundle/upload_00.png",
                    raw_value="Test Person A",
                    normalized_value="test person a",
                ),
                FieldEvidence(
                    document_type="address_proof",
                    source_path="/tmp/fake-bundle/upload_01.png",
                    raw_value="Test Person B",
                    normalized_value="test person b",
                ),
            ],
        )
    ],
    summary={"total_findings": 1, "highest_severity": "HIGH"},
    warnings=[],
)

# ---------------------------------------------------------------------------
# In-memory SQLite engine and session factory used by persist tests
# ---------------------------------------------------------------------------

@pytest.fixture()
def sqlite_engine():
    """
    Create a fresh in-memory SQLite engine with the YONKO schema.

    Uses StaticPool so every connection (from the route helper and from the
    test's assertion queries) shares the same in-memory database.  Without
    StaticPool, each `engine.connect()` call in SQLite `sqlite://` creates a
    new ephemeral database and tables created by `create_all` on one connection
    are invisible to later connections.
    """
    from sqlalchemy.pool import StaticPool

    engine = create_engine(
        "sqlite://",  # pure in-memory, no file
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,  # share a single connection — required for sqlite://
    )
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture()
def override_db(sqlite_engine, monkeypatch):
    """
    Replace app.database.engine and SessionLocal with the in-memory SQLite
    equivalents so that _persist_bundle writes to SQLite, not Postgres.

    We also patch app.api.routes.get_db so the helper's `next(get_db())`
    call pulls sessions from the test engine.
    """
    import app.database as db_module
    import app.api.routes as routes_module

    TestSessionLocal = sessionmaker(
        bind=sqlite_engine, autocommit=False, autoflush=False
    )

    def _test_get_db():
        session = TestSessionLocal()
        try:
            yield session
        finally:
            session.close()

    monkeypatch.setattr(db_module, "engine", sqlite_engine)
    monkeypatch.setattr(db_module, "SessionLocal", TestSessionLocal)
    monkeypatch.setattr(routes_module, "get_db", _test_get_db)
    return sqlite_engine


# ---------------------------------------------------------------------------
# Helper: build a minimal two-file multipart POST payload using bytes
# ---------------------------------------------------------------------------

def _fake_png_payload():
    """Return a minimal 1×1 white PNG as bytes (valid but tiny image)."""
    # A real minimal PNG: 1×1 pixel, white, no compression tricks needed
    import io
    from PIL import Image as PILImage
    buf = io.BytesIO()
    img = PILImage.new("RGB", (8, 8), color=(255, 255, 255))
    img.save(buf, format="PNG")
    return buf.getvalue()


def _upload_files():
    """Two minimal PNG uploads that pass the route's validation."""
    png = _fake_png_payload()
    return [
        ("files", ("doc_a.png", png, "image/png")),
        ("files", ("doc_b.png", png, "image/png")),
    ]


def _auth_headers():
    """Create a synthetic citizen in the patched DB and return auth headers.

    POST /analyze is auth-protected; persist tests need a valid token whose
    user also satisfies the bundles.owner_email FK when persistence is on.
    """
    import uuid as _uuid

    from app.auth.tokens import create_access_token
    from app.database import SessionLocal
    from app.models import UserPg

    session = SessionLocal()
    try:
        user = UserPg(
            email=f"persist-{_uuid.uuid4().hex[:8]}@synthetic.example.com",
            password_hash="not-a-real-hash",
            role="citizen",
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        token, _ = create_access_token(user.id, "citizen", mfa_ok=True)
        return {"Authorization": f"Bearer {token}"}
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_persist_false_does_not_write_db(monkeypatch, override_db):
    """
    With PERSIST_RESULTS=False (default) a successful /analyze call must NOT
    create any Bundle row in the database.
    """
    import app.api.routes as routes_module
    import app.config as config_module

    # Monkeypatch detect_bundle to return our synthetic result
    monkeypatch.setattr(routes_module, "detect_bundle", lambda _dir: FAKE_RESULT)
    # Ensure PERSIST_RESULTS is False (should be default, but be explicit)
    monkeypatch.setattr(config_module.settings, "PERSIST_RESULTS", False)

    client = TestClient(app)
    response = client.post(
        "/analyze", files=_upload_files(), headers=_auth_headers()
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["documents_processed"] == 2

    # No Bundle row should exist in the in-memory DB
    from sqlalchemy.orm import Session
    with Session(override_db) as sess:
        count = sess.query(Bundle).count()
    assert count == 0, f"Expected 0 Bundle rows, got {count}"


def test_persist_true_saves_bundle(monkeypatch, override_db):
    """
    With PERSIST_RESULTS=True a successful /analyze call must create exactly
    one Bundle row in the database without altering the response shape.
    """
    import app.api.routes as routes_module
    import app.config as config_module

    monkeypatch.setattr(routes_module, "detect_bundle", lambda _dir: FAKE_RESULT)
    monkeypatch.setattr(config_module.settings, "PERSIST_RESULTS", True)

    client = TestClient(app)
    response = client.post(
        "/analyze", files=_upload_files(), headers=_auth_headers()
    )

    assert response.status_code == 200, response.text

    # Verify response contract is unchanged (key presence + types)
    body = response.json()
    assert "bundle_path" in body
    assert "documents_processed" in body
    assert "findings" in body
    assert "summary" in body
    assert "warnings" in body
    assert isinstance(body["findings"], list)

    # Exactly one Bundle row must have been created
    from sqlalchemy.orm import Session
    with Session(override_db) as sess:
        bundles = sess.query(Bundle).all()
    assert len(bundles) == 1, f"Expected 1 Bundle row, got {len(bundles)}"
    # bundle_ref is the temp dir name — not empty
    assert bundles[0].bundle_ref, "bundle_ref must be non-empty"


def test_persist_failure_does_not_break_analyze(monkeypatch, override_db):
    """
    If _persist_bundle raises an exception the /analyze endpoint must still
    return HTTP 200 with the normal analysis payload.

    This verifies the fire-and-forget / fault-isolation contract: a DB write
    failure is logged but never propagates to the HTTP response.
    """
    import app.api.routes as routes_module
    import app.config as config_module

    monkeypatch.setattr(routes_module, "detect_bundle", lambda _dir: FAKE_RESULT)
    monkeypatch.setattr(config_module.settings, "PERSIST_RESULTS", True)

    # Simulate a DB failure by making _persist_bundle raise unconditionally
    def _broken_persist(result, temp_dir, user=None):
        raise RuntimeError("Simulated database write failure")

    monkeypatch.setattr(routes_module, "_persist_bundle", _broken_persist)

    client = TestClient(app)
    response = client.post(
        "/analyze", files=_upload_files(), headers=_auth_headers()
    )

    # The route must return 200 despite the persist failure
    assert response.status_code == 200, (
        f"Expected 200 but got {response.status_code}. "
        "DB failures must not propagate to the HTTP response."
    )
    body = response.json()
    assert "findings" in body
    assert "summary" in body
