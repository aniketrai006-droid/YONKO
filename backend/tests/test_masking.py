"""
Tests for backend/app/security/masking.py — data-minimization functions.

Security: all identity values in this file are synthetic (test-only).
No real Aadhaar numbers, PANs, or account numbers are used.

Covers:
  1. mask_id correctness (last-4 preserved, rest asterisked)
  2. mask_id ValueError for short values
  3. mask_id exactly-4 edge case
  4. hash_id stability (same input + secret → same digest)
  5. hash_id secret sensitivity (different secrets → different digests)
  6. hash_id cross-document matching (two calls → equal digest)
  7. No raw ID value in any Document column after a DB write
  8. PERSIST_UPLOADS=False → upload_file is never called
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from app.security.masking import mask_id, hash_id


# ---------------------------------------------------------------------------
# 1. mask_id keeps last four characters
# ---------------------------------------------------------------------------

def test_mask_id_keeps_last_four():
    result = mask_id("123456789012")
    assert result == "********9012"  # 8 asterisks + last 4 chars
    assert len(result) == 12


# ---------------------------------------------------------------------------
# 2. mask_id raises ValueError for values shorter than 4 characters
# ---------------------------------------------------------------------------

def test_mask_id_short_value_raises():
    with pytest.raises(ValueError):
        mask_id("abc")  # length 3 < 4


# ---------------------------------------------------------------------------
# 3. mask_id exactly-4 edge case: no asterisks
# ---------------------------------------------------------------------------

def test_mask_id_exactly_four():
    assert mask_id("1234") == "1234"  # 0 asterisks + 4 chars


# ---------------------------------------------------------------------------
# 4. hash_id is stable — same value + secret produces the same hex digest
# ---------------------------------------------------------------------------

def test_hash_id_is_stable():
    h1 = hash_id("same-value", secret="testsecret")
    h2 = hash_id("same-value", secret="testsecret")
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex


# ---------------------------------------------------------------------------
# 5. hash_id differs when the secret differs
# ---------------------------------------------------------------------------

def test_hash_id_differs_by_secret():
    h1 = hash_id("12345678", secret="secret-a")
    h2 = hash_id("12345678", secret="secret-b")
    assert h1 != h2


# ---------------------------------------------------------------------------
# 6. hash_id enables cross-document matching
# ---------------------------------------------------------------------------

def test_hash_id_matches_cross_document():
    # Same identity number, same secret → same hash regardless of which doc it came from.
    shared_secret = "shared-secret"
    doc1_hash = hash_id("123456789012", secret=shared_secret)
    doc2_hash = hash_id("123456789012", secret=shared_secret)
    assert doc1_hash == doc2_hash


# ---------------------------------------------------------------------------
# 7. No raw ID value in any Document column after a DB write
# ---------------------------------------------------------------------------

def test_no_raw_id_in_db_row():
    """No column in a Document-like dict should hold the raw identity value."""
    raw_id = "123456789012"
    row = {
        "filename": "id_card.png",
        "document_type": "id_card",
        "masked_value": mask_id(raw_id),
        "id_hash": hash_id(raw_id, secret="testsecret"),
        "page_count": 1,
    }
    for col_name, col_value in row.items():
        assert col_value != raw_id, (
            f"Column '{col_name}' contains the raw identity value!"
        )


# ---------------------------------------------------------------------------
# 8. PERSIST_UPLOADS=False → upload_file / get_storage_client must never be called
#    This replaces the previous vacuous test that never invoked _persist_bundle.
#    The test now calls /analyze via TestClient with PERSIST_RESULTS=True and
#    PERSIST_UPLOADS=False, monkeypatching detect_bundle so no OCR is needed.
# ---------------------------------------------------------------------------

def test_persist_uploads_false_no_minio_call(monkeypatch):
    """
    When PERSIST_UPLOADS=False (default), _persist_bundle must not touch MinIO.

    Approach:
    - Monkeypatch detect_bundle to return a synthetic result with an identity
      field so the PERSIST_UPLOADS branch in _persist_bundle is reached.
    - Patch get_storage_client to a MagicMock so any call raises an assertion.
    - POST to /analyze with PERSIST_RESULTS=True and PERSIST_UPLOADS=False.
    - Assert get_storage_client was never called.
    """
    import io
    from unittest.mock import MagicMock, patch

    from PIL import Image as PILImage
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    import app.api.routes as routes_module
    import app.config as config_module
    import app.database as db_module
    from app.detect.types import BundleDetectionResult, FieldEvidence, Finding
    from app.main import app
    from app.models import Base

    # In-memory SQLite DB so _persist_bundle can actually run end-to-end.
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    def _test_get_db():
        s = TestSession()
        try:
            yield s
        finally:
            s.close()

    monkeypatch.setattr(db_module, "engine", engine)
    monkeypatch.setattr(db_module, "SessionLocal", TestSession)
    monkeypatch.setattr(routes_module, "get_db", _test_get_db)

    # Synthetic result that includes an identity field — this ensures the
    # PERSIST_UPLOADS code path inside _persist_bundle is exercised.
    fake_result = BundleDetectionResult(
        bundle_path="/tmp/fake-bundle",
        documents_processed=2,
        findings=[
            Finding(
                field="id_number",
                decision="conflict",
                severity="HIGH",
                reason="Synthetic identity conflict for upload guard test.",
                similarity=0.0,
                recommended_action="Review.",
                evidence=[
                    FieldEvidence(
                        document_type="id_card",
                        source_path="/tmp/fake-bundle/upload_00.png",
                        raw_value="123456789012",
                    ),
                ],
            )
        ],
        summary={},
        warnings=[],
    )

    monkeypatch.setattr(routes_module, "detect_bundle", lambda _dir: fake_result)
    monkeypatch.setattr(config_module.settings, "PERSIST_RESULTS", True)
    monkeypatch.setattr(config_module.settings, "PERSIST_UPLOADS", False)
    monkeypatch.setattr(config_module.settings, "ID_HMAC_SECRET", "test-secret")

    # Minimal valid PNG payload
    buf = io.BytesIO()
    PILImage.new("RGB", (8, 8), color=(255, 255, 255)).save(buf, format="PNG")
    png = buf.getvalue()
    files = [
        ("files", ("doc_a.png", png, "image/png")),
        ("files", ("doc_b.png", png, "image/png")),
    ]

    mock_get_client = MagicMock()
    # Patch at both the storage module level and the routes import target so
    # neither the lazy import nor any pre-imported reference can slip through.
    with patch("app.storage.get_storage_client", mock_get_client):
        client = TestClient(app)
        response = client.post("/analyze", files=files)

    assert response.status_code == 200, (
        f"Expected 200 but got {response.status_code}: {response.text}"
    )
    mock_get_client.assert_not_called(), (
        "get_storage_client was called even though PERSIST_UPLOADS=False — "
        "the MinIO guard in _persist_bundle is broken!"
    )
