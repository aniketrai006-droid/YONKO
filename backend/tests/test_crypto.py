"""Tests for field-level encryption at rest (app.security.crypto).

Covers steering rule 8: unique ciphertext per encryption, round-trip
decrypt, tamper detection, key-id rotation, and — via raw SQL — that PII
columns are unreadable without the application keys. All values are
synthetic.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.security.crypto import (
    InvalidTokenError,
    active_key_id,
    decrypt_field,
    encrypt_field,
    generate_data_key,
    hmac_field,
)


@pytest.fixture()
def data_keys(monkeypatch):
    """Configure a deterministic two-key ring for the test."""
    key_v1 = "a" * 64
    key_v2 = "b" * 64
    monkeypatch.setenv("DATA_KEY_V1", key_v1)
    monkeypatch.setenv("DATA_KEY_V2", key_v2)
    monkeypatch.setenv("DATA_KEY_ACTIVE", "v1")
    return {"v1": key_v1, "v2": key_v2}


# ---------------------------------------------------------------------------
# 1. Core encrypt/decrypt behaviour
# ---------------------------------------------------------------------------

def test_ciphertext_differs_for_equal_plaintexts(data_keys):
    """Same plaintext twice must produce different ciphertexts (random nonce)."""
    ct1 = encrypt_field("Aadhaar 1234-5678-9012")
    ct2 = encrypt_field("Aadhaar 1234-5678-9012")
    assert ct1 != ct2
    assert decrypt_field(ct1) == decrypt_field(ct2) == "Aadhaar 1234-5678-9012"


def test_decrypt_round_trips(data_keys):
    for plaintext in ("", "x", "Synthetic Name: Test Person", "üñïçödé ✓", "a" * 5000):
        assert decrypt_field(encrypt_field(plaintext)) == plaintext


def test_token_carries_key_id(data_keys):
    token = encrypt_field("secret-value")
    assert token.startswith("enc:v1:v1:")


def test_tampered_ciphertext_fails(data_keys):
    """Any bit-flip in the payload must raise — GCM authenticates."""
    token = encrypt_field("sensitive evidence quote")
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    with pytest.raises(InvalidTokenError):
        decrypt_field(tampered)


def test_plaintext_passes_through_unchanged(data_keys):
    """Legacy plaintext rows (no enc: prefix) are returned as-is."""
    assert decrypt_field("not-encrypted") == "not-encrypted"
    assert decrypt_field("") == ""
    assert decrypt_field(None) is None


def test_already_encrypted_value_is_not_double_encrypted(data_keys):
    token = encrypt_field("value")
    assert encrypt_field(token) == token


# ---------------------------------------------------------------------------
# 2. Key rotation
# ---------------------------------------------------------------------------

def test_rotation_decrypts_with_old_key_and_encrypts_with_new(
    data_keys, monkeypatch
):
    old_token = encrypt_field("rotate me", key_id="v1")
    assert decrypt_field(old_token) == "rotate me"

    # Switch the active key to v2; v1 stays in the ring for decryption.
    monkeypatch.setenv("DATA_KEY_ACTIVE", "v2")
    assert active_key_id() == "v2"
    new_token = encrypt_field("rotate me")
    assert new_token.startswith("enc:v1:v2:")
    # Both tokens still decrypt during the transition window.
    assert decrypt_field(old_token) == "rotate me"
    assert decrypt_field(new_token) == "rotate me"


def test_missing_key_for_token_raises(data_keys, monkeypatch):
    token = encrypt_field("value", key_id="v2")
    monkeypatch.delenv("DATA_KEY_V2")
    with pytest.raises(InvalidTokenError):
        decrypt_field(token)


def test_active_key_must_exist(data_keys, monkeypatch):
    monkeypatch.setenv("DATA_KEY_ACTIVE", "v9")
    with pytest.raises(RuntimeError):
        active_key_id()


def test_generate_data_key_is_32_bytes_hex():
    key = generate_data_key()
    assert len(key) == 64
    bytes.fromhex(key)  # valid hex, no exception


# ---------------------------------------------------------------------------
# 3. Searchable HMAC
# ---------------------------------------------------------------------------

def test_hmac_is_deterministic(data_keys):
    assert hmac_field("same-value") == hmac_field("same-value")


def test_hmac_differs_by_value_and_domain(data_keys):
    assert hmac_field("a") != hmac_field("b")


# ---------------------------------------------------------------------------
# 4. ORM integration + raw SQL unreadability
# ---------------------------------------------------------------------------

@pytest.fixture()
def engine():
    """In-memory SQLite with the full YONKO schema."""
    from app.models import Base

    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)
    eng.dispose()


@pytest.fixture()
def session(engine, data_keys):
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    db = factory()
    try:
        yield db
    finally:
        db.close()


def _seed_user_and_finding(session, reason_text):
    """Insert a user + bundle + finding with the given reason text."""
    from app.models import Bundle, FindingPg, UserPg

    user = UserPg(
        email=f"citizen-{uuid.uuid4().hex[:8]}@synthetic.example.com",
        password_hash="not-a-real-hash",
        role="citizen",
    )
    session.add(user)
    session.flush()

    bundle = Bundle(
        owner_email=user.email,
        owner_id=user.id,
        bundle_ref=f"synthetic-{uuid.uuid4().hex[:8]}",
    )
    session.add(bundle)
    session.flush()

    finding = FindingPg(
        bundle_id=bundle.id,
        field="name",
        decision="conflict",
        severity="HIGH",
        reason=reason_text,
    )
    session.add(finding)
    session.commit()
    return finding


def test_orm_round_trip_decrypts_on_read(session, data_keys):
    quote = "Synthetic conflict: Test Person A vs Test Person B"
    finding = _seed_user_and_finding(session, quote)
    assert finding.reason == quote


def test_raw_sql_select_returns_ciphertext_not_plaintext(session, data_keys):
    """The acceptance criterion: a raw SELECT on a PII column shows ciphertext."""
    plaintext = "Synthetic conflict: Aadhaar 1111-2222-3333 vs 4444-5555-6666"
    _seed_user_and_finding(session, plaintext)

    rows = session.execute(text("SELECT reason FROM findings_pg")).fetchall()
    assert rows, "expected one seeded row"
    stored = rows[0][0]
    assert stored.startswith("enc:v1:"), stored
    assert plaintext not in stored
    assert "1111" not in stored and "Aadhaar" not in stored


def test_raw_sql_select_totp_secret_is_ciphertext(session, data_keys):
    """users_pg.totp_secret must also be unreadable via raw SQL."""
    from app.models import UserPg

    secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    user = UserPg(
        email=f"mfa-{uuid.uuid4().hex[:8]}@synthetic.example.com",
        password_hash="not-a-real-hash",
        role="reviewer",
        totp_secret=secret,
    )
    session.add(user)
    session.commit()

    stored = session.execute(text("SELECT totp_secret FROM users_pg")).scalar_one()
    assert stored.startswith("enc:v1:")
    assert secret not in stored
    # But the ORM hands the plaintext back to the application.
    session.expire_all()
    reloaded = session.query(UserPg).one()
    assert reloaded.totp_secret == secret


def test_raw_sql_select_reviewer_email_is_ciphertext(session, data_keys):
    """review_decisions.reviewer_email must be unreadable via raw SQL."""
    from app.models import ReviewDecision, UserPg

    user = UserPg(
        email=f"decider-{uuid.uuid4().hex[:8]}@synthetic.example.com",
        password_hash="x",
        role="reviewer",
    )
    session.add(user)
    session.flush()

    finding = _seed_user_and_finding(session, None)
    email = "reviewer@synthetic.example.com"
    decision = ReviewDecision(
        finding_id=finding.id,
        reviewer_id=user.id,
        reviewer_email=email,
        decision="accepted",
    )
    session.add(decision)
    session.commit()

    stored = session.execute(
        text("SELECT reviewer_email FROM review_decisions")
    ).scalar_one()
    assert stored.startswith("enc:v1:")
    assert email not in stored
    session.expire_all()
    assert session.query(ReviewDecision).one().reviewer_email == email


def test_rotation_loop_reencrypts_rows(session, data_keys, monkeypatch):
    """Simulate scripts/rotate_data_keys.py: decrypt old-key rows, rewrite
    with the active key, and confirm the ORM still round-trips."""
    from app.models import FindingPg

    _seed_user_and_finding(session, "rotate this reason")

    old_token = encrypt_field("rotate this reason", key_id="v1")
    session.execute(
        text("UPDATE findings_pg SET reason = :value"), {"value": old_token}
    )
    session.commit()

    monkeypatch.setenv("DATA_KEY_ACTIVE", "v2")

    rows = session.execute(text("SELECT id, reason FROM findings_pg")).fetchall()
    for row_id, value in rows:
        plaintext = decrypt_field(value)
        new_value = encrypt_field(plaintext)  # active key = v2
        session.execute(
            text("UPDATE findings_pg SET reason = :value WHERE id = :row_id"),
            {"value": new_value, "row_id": row_id},
        )
    session.commit()

    stored = session.execute(text("SELECT reason FROM findings_pg")).scalar_one()
    assert stored.startswith("enc:v1:v2:")
    session.expire_all()
    assert session.query(FindingPg).one().reason == "rotate this reason"

    assert hmac_field("a", domain="email") != hmac_field("a", domain="phone")
