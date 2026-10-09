"""JWT auth tests: register/login/refresh/logout/me, MFA, lockout, roles.

Covers steering rule 6 (401 unauthenticated / 403 wrong role), rule 7 (audit
rows contain opaque UUIDs only), and rule 8 (expired tokens rejected, refresh
rotation + theft detection, TOTP flow). All identities here are synthetic.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pyotp
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth.deps import require_role
from app.auth.tokens import create_access_token
from app.config import settings
from app.database import get_db
from app.main import app as main_app
from app.models import AuditLogPg, Base, RefreshToken, UserPg

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def client(tmp_path, monkeypatch):
    """TestClient wired to an in-memory SQLite DB and a fixed JWT secret."""
    monkeypatch.setattr(settings, "JWT_SECRET", "unit-test-secret-" + uuid.uuid4().hex)
    # Keep lockout tests fast/deterministic.
    monkeypatch.setattr(settings, "AUTH_MAX_FAILED_ATTEMPTS", 5)
    monkeypatch.setattr(settings, "AUTH_LOCKOUT_MINUTES", 15)

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    def _get_db():
        session = TestingSession()
        try:
            yield session
        finally:
            session.close()

    main_app.dependency_overrides[get_db] = _get_db
    # Also expose for assertions inside tests.
    client_bind = TestClient(main_app)
    client_bind.TestSession = TestingSession  # type: ignore[attr-defined]
    try:
        yield client_bind
    finally:
        main_app.dependency_overrides.clear()


@pytest.fixture()
def session_factory(client):
    return client.TestSession


# ---------------------------------------------------------------------------
# Test-only app with require_role-guarded endpoints
# ---------------------------------------------------------------------------

def _build_role_app() -> FastAPI:
    """Small app reusing the real auth router plus role-guarded probes."""
    from app.api.auth_jwt_routes import router as auth_jwt_router

    probe = FastAPI()
    probe.include_router(auth_jwt_router)

    @probe.get("/probe/reviewer")
    def _reviewer_probe(user: UserPg = Depends(require_role("reviewer"))):
        return {"role": user.role}

    @probe.get("/probe/admin")
    def _admin_probe(user: UserPg = Depends(require_role("admin"))):
        return {"role": user.role}

    return probe


@pytest.fixture()
def role_client(client):
    """Client for an app with /probe/reviewer and /probe/admin endpoints."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    def _get_db():
        session = TestingSession()
        try:
            yield session
        finally:
            session.close()

    app = _build_role_app()
    app.dependency_overrides[get_db] = _get_db
    tc = TestClient(app)
    tc.TestSession = TestingSession  # type: ignore[attr-defined]
    try:
        yield tc
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PASSWORD = "Synthetic-Passw0rd"


def _register(client, email: str, password: str = PASSWORD, role: str = "citizen"):
    return client.post(
        "/auth/register",
        json={"email": email, "password": password, "role": role},
    )


def _login(client, email: str, password: str = PASSWORD, totp_code: str | None = None):
    body = {"email": email, "password": password}
    if totp_code is not None:
        body["totp_code"] = totp_code
    return client.post("/auth/login", json=body)


def _auth_header(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def _provision_reviewer(client, session_factory, email: str = "reviewer@synthetic.example.com"):
    """Create a reviewer directly in the DB (self-registration is citizen-only)."""
    from app.auth.passwords import hash_password
    session = session_factory()
    try:
        user = UserPg(email=email, password_hash=hash_password(PASSWORD), role="reviewer")
        session.add(user)
        session.commit()
        session.refresh(user)
        return user.id
    finally:
        session.close()


def _enroll_mfa(client, tokens: dict) -> dict:
    """Enroll MFA for the token's user and return the provisioning payload."""
    response = client.post("/auth/mfa/enroll", headers=_auth_header(tokens))
    assert response.status_code == 200, response.text
    return response.json()


def _totp_code(provisioning: dict) -> str:
    return pyotp.TOTP(provisioning["secret"]).now()



# ---------------------------------------------------------------------------
# 1. Registration
# ---------------------------------------------------------------------------

def test_register_citizen_succeeds(client):
    response = _register(client, "citizen@synthetic.example.com")
    assert response.status_code == 201
    body = response.json()
    assert body["role"] == "citizen"
    assert body["email"] == "citizen@synthetic.example.com"
    # Never leak the password hash or any token in the register response.
    assert "password_hash" not in body
    assert "access_token" not in body


def test_register_reviewer_role_is_forbidden(client):
    """Self-registration must not grant elevated roles (privilege escalation)."""
    response = _register(client, "sneaky@synthetic.example.com", role="reviewer")
    assert response.status_code == 403


def test_register_weak_password_rejected(client):
    response = _register(client, "weak@synthetic.example.com", password="short1")
    assert response.status_code == 400
    assert "12" in response.json()["detail"]


def test_register_password_without_digit_rejected(client):
    response = _register(
        client, "nodigit@synthetic.example.com", password="OnlyLettersHere"
    )
    assert response.status_code == 400


def test_register_duplicate_email_conflicts(client):
    _register(client, "dup@synthetic.example.com")
    again = _register(client, "dup@synthetic.example.com")
    assert again.status_code == 409


# ---------------------------------------------------------------------------
# 2. Login, /auth/me, and token behaviour
# ---------------------------------------------------------------------------

def test_login_with_wrong_password_returns_401(client):
    _register(client, "wrongpw@synthetic.example.com")
    response = _login(client, "wrongpw@synthetic.example.com", password="Incorrect-Passw0rd")
    assert response.status_code == 401


def test_login_unknown_email_returns_401(client):
    response = _login(client, "ghost@synthetic.example.com")
    assert response.status_code == 401


def test_login_success_returns_token_pair(client):
    _register(client, "okuser@synthetic.example.com")
    response = _login(client, "okuser@synthetic.example.com")
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["expires_in"] == settings.AUTH_ACCESS_TOKEN_TTL_MINUTES * 60


def test_me_requires_authentication(client):
    assert client.get("/auth/me").status_code == 401


def test_me_with_garbage_token_returns_401(client):
    response = client.get(
        "/auth/me", headers={"Authorization": "Bearer not.a.token"}
    )
    assert response.status_code == 401


def test_me_returns_profile(client):
    _register(client, "profile@synthetic.example.com")
    tokens = _login(client, "profile@synthetic.example.com").json()
    response = client.get("/auth/me", headers=_auth_header(tokens))
    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "profile@synthetic.example.com"
    assert body["role"] == "citizen"
    assert body["mfa_enrolled"] is False


def test_expired_access_token_returns_401(client, session_factory):
    """Craft a token that expired 1 minute ago; /auth/me must reject it."""
    import jwt as pyjwt
    from app.auth.tokens import ALGORITHM, _signing_key

    session = session_factory()
    try:
        user = UserPg(
            email="expired@synthetic.example.com",
            password_hash="x",  # never used for verification here
            role="citizen",
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        user_id = user.id
    finally:
        session.close()

    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "role": "citizen",
        "mfa_ok": True,
        "type": "access",
        "iat": now - timedelta(minutes=16),
        "exp": now - timedelta(minutes=1),
        "jti": uuid.uuid4().hex,
    }
    expired = pyjwt.encode(payload, _signing_key("access"), algorithm=ALGORITHM)
    response = client.get(
        "/auth/me", headers={"Authorization": f"Bearer {expired}"}
    )
    assert response.status_code == 401


def test_token_signed_with_wrong_key_returns_401(client):
    """A token signed by a different key must be rejected."""
    import jwt as pyjwt

    _register(client, "wrongkey@synthetic.example.com")
    _login(client, "wrongkey@synthetic.example.com")
    session = client.TestSession()
    try:
        user = session.execute(
            select(UserPg).where(UserPg.email == "wrongkey@synthetic.example.com")
        ).scalar_one()
        user_id = user.id
    finally:
        session.close()

    payload = {
        "sub": str(user_id),
        "role": "citizen",
        "mfa_ok": True,
        "type": "access",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
        "jti": uuid.uuid4().hex,
    }
    forged = pyjwt.encode(
        payload, b"attacker-key-0123456789abcdefghijklmnop", algorithm="HS256"
    )
    response = client.get(
        "/auth/me", headers={"Authorization": f"Bearer {forged}"}
    )


# ---------------------------------------------------------------------------
# 3. Refresh-token rotation and theft detection
# ---------------------------------------------------------------------------

def test_refresh_rotates_token_pair(client):
    _register(client, "rotate@synthetic.example.com")
    tokens = _login(client, "rotate@synthetic.example.com").json()
    response = client.post(
        "/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["access_token"]
    assert body["refresh_token"] != tokens["refresh_token"]


def test_refresh_with_garbage_token_returns_401(client):
    response = client.post("/auth/refresh", json={"refresh_token": "garbage"})
    assert response.status_code == 401


def test_refresh_reuse_revokes_whole_family(client):
    """Presenting an already-rotated refresh token = theft: family dies."""
    _register(client, "reuse@synthetic.example.com")
    tokens = _login(client, "reuse@synthetic.example.com").json()
    old_refresh = tokens["refresh_token"]

    first = client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert first.status_code == 200
    rotated = first.json()

    # Replay the consumed token: must 401 and revoke the family.
    replay = client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert replay.status_code == 401

    # The legitimately rotated token is now also dead (same family).
    after = client.post(
        "/auth/refresh", json={"refresh_token": rotated["refresh_token"]}
    )
    assert after.status_code == 401


def test_logout_revokes_refresh_family(client):
    _register(client, "logout@synthetic.example.com")
    tokens = _login(client, "logout@synthetic.example.com").json()

    response = client.post(
        "/auth/logout",
        headers=_auth_header(tokens),
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert response.status_code == 200

    # The revoked family cannot refresh anymore.
    after = client.post(
        "/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert after.status_code == 401


def test_logout_requires_valid_access_token(client):
    _register(client, "logout-noauth@synthetic.example.com")
    tokens = _login(client, "logout-noauth@synthetic.example.com").json()
    response = client.post(
        "/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# 4. Account lockout
# ---------------------------------------------------------------------------

def test_lockout_after_repeated_failed_logins(client):
    _register(client, "lockout@synthetic.example.com")
    for _ in range(settings.AUTH_MAX_FAILED_ATTEMPTS):
        resp = _login(client, "lockout@synthetic.example.com", password="Wrong-Passw0rd")
        assert resp.status_code == 401

    # Even the correct password is rejected while locked.
    resp = _login(client, "lockout@synthetic.example.com")
    assert resp.status_code == 429


def test_locked_account_cannot_use_existing_token(client):
    """Tokens issued before lockout stop working while the lock is active."""
    _register(client, "lockedtoken@synthetic.example.com")
    tokens = _login(client, "lockedtoken@synthetic.example.com").json()
    assert client.get("/auth/me", headers=_auth_header(tokens)).status_code == 200

    for _ in range(settings.AUTH_MAX_FAILED_ATTEMPTS):
        _login(client, "lockedtoken@synthetic.example.com", password="Wrong-Passw0rd")

    response = client.get("/auth/me", headers=_auth_header(tokens))
    assert response.status_code == 401



# ---------------------------------------------------------------------------
# 5. require_role: 401 unauthenticated / 403 wrong role
# ---------------------------------------------------------------------------

def test_role_probe_requires_authentication(role_client):
    assert role_client.get("/probe/reviewer").status_code == 401
    assert role_client.get("/probe/admin").status_code == 401


def test_citizen_gets_403_on_reviewer_endpoint(role_client):
    _register(role_client, "citizen-role@synthetic.example.com")
    tokens = _login(role_client, "citizen-role@synthetic.example.com").json()
    response = role_client.get("/probe/reviewer", headers=_auth_header(tokens))
    assert response.status_code == 403


def test_citizen_gets_403_on_admin_endpoint(role_client):
    _register(role_client, "citizen-admin@synthetic.example.com")
    tokens = _login(role_client, "citizen-admin@synthetic.example.com").json()
    response = role_client.get("/probe/admin", headers=_auth_header(tokens))
    assert response.status_code == 403


def test_reviewer_gets_403_on_admin_endpoint(role_client):
    """A fully-MFA-authenticated reviewer still cannot reach admin endpoints."""
    _provision_reviewer(role_client, role_client.TestSession,
                        "rev-admin@synthetic.example.com")
    tokens = _login(role_client, "rev-admin@synthetic.example.com").json()
    provisioning = _enroll_mfa(role_client, tokens)
    tokens = _login(
        role_client, "rev-admin@synthetic.example.com",
        totp_code=_totp_code(provisioning),
    ).json()
    response = role_client.get("/probe/admin", headers=_auth_header(tokens))
    assert response.status_code == 403


def test_admin_reaches_admin_endpoint(role_client):
    from app.auth.passwords import hash_password
    session = role_client.TestSession()
    try:
        admin = UserPg(
            email="admin@synthetic.example.com",
            password_hash=hash_password(PASSWORD),
            role="admin",
        )
        session.add(admin)
        session.commit()
    finally:
        session.close()

    # Pre-enrollment bootstrap token (mfa_ok=False) cannot pass get_current_user.
    tokens = _login(role_client, "admin@synthetic.example.com").json()
    blocked = role_client.get("/probe/admin", headers=_auth_header(tokens))
    assert blocked.status_code == 401

    # After enrolling and logging in with a TOTP code, the admin passes.
    provisioning = _enroll_mfa(role_client, tokens)
    tokens = _login(
        role_client, "admin@synthetic.example.com", totp_code=_totp_code(provisioning)
    ).json()
    response = role_client.get("/probe/admin", headers=_auth_header(tokens))
    assert response.status_code == 200
    assert response.json()["role"] == "admin"


# ---------------------------------------------------------------------------
# 6. TOTP MFA for reviewer/admin
# ---------------------------------------------------------------------------

def test_reviewer_bootstrap_login_is_not_fully_authenticated(client, session_factory):
    """Password-only login works pre-enrollment, but /auth/me rejects the token."""
    _provision_reviewer(client, session_factory)
    response = _login(client, "reviewer@synthetic.example.com")
    assert response.status_code == 200
    tokens = response.json()
    assert tokens["mfa_ok"] is False
    # get_current_user requires mfa_ok for reviewer tokens.
    me = client.get("/auth/me", headers=_auth_header(tokens))
    assert me.status_code == 401


def test_mfa_enroll_returns_provisioning_uri(client, session_factory):
    """A reviewer's bootstrap (password-only) token can reach /auth/mfa/enroll."""
    _provision_reviewer(client, session_factory, "enroll@synthetic.example.com")
    tokens = _login(client, "enroll@synthetic.example.com").json()
    assert tokens["mfa_ok"] is False  # pre-enrollment bootstrap

    response = client.post("/auth/mfa/enroll", headers=_auth_header(tokens))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["provisioning_uri"].startswith("otpauth://totp/")
    assert len(body["secret"]) >= 32


def test_mfa_enroll_without_token_rejected(client):
    assert client.post("/auth/mfa/enroll").status_code == 401


def test_reviewer_login_with_totp_code_succeeds(client, session_factory):
    _provision_reviewer(client, session_factory, "totp@synthetic.example.com")
    tokens = _login(client, "totp@synthetic.example.com").json()
    provisioning = _enroll_mfa(client, tokens)

    response = _login(
        client, "totp@synthetic.example.com", totp_code=_totp_code(provisioning)
    )
    assert response.status_code == 200
    body = response.json()
    assert body["mfa_ok"] is True
    # Now /auth/me accepts the token.
    me = client.get("/auth/me", headers=_auth_header(body))
    assert me.status_code == 200


def test_reviewer_login_with_wrong_totp_code_rejected(client, session_factory):
    _provision_reviewer(client, session_factory, "badtotp@synthetic.example.com")
    tokens = _login(client, "badtotp@synthetic.example.com").json()
    _enroll_mfa(client, tokens)

    response = _login(client, "badtotp@synthetic.example.com", totp_code="000000")
    assert response.status_code == 401


def test_reviewer_login_without_code_after_enrollment_rejected(client, session_factory):
    _provision_reviewer(client, session_factory, "nocode@synthetic.example.com")
    tokens = _login(client, "nocode@synthetic.example.com").json()
    _enroll_mfa(client, tokens)

    response = _login(client, "nocode@synthetic.example.com")
    assert response.status_code == 401


def test_double_mfa_enrollment_conflicts(client, session_factory):
    _provision_reviewer(client, session_factory, "twice@synthetic.example.com")
    tokens = _login(client, "twice@synthetic.example.com").json()
    _enroll_mfa(client, tokens)
    # Re-enroll with a TOTP-verified token.
    secret = _stored_totp_secret(client, "twice@synthetic.example.com")
    tokens = _login(
        client, "twice@synthetic.example.com", totp_code=pyotp.TOTP(secret).now()
    ).json()
    response = client.post("/auth/mfa/enroll", headers=_auth_header(tokens))
    assert response.status_code == 409


def test_citizen_login_is_always_fully_authenticated(client):
    """Citizens do not need MFA; their tokens carry mfa_ok=True."""
    _register(client, "nomfa@synthetic.example.com")
    tokens = _login(client, "nomfa@synthetic.example.com").json()
    assert tokens["mfa_ok"] is True
    assert client.get("/auth/me", headers=_auth_header(tokens)).status_code == 200


def _stored_totp_secret(client, email: str) -> str:
    """Test helper: decrypt the stored TOTP secret for an enrolled user."""
    from app.auth.totp import decrypt_secret
    session = client.TestSession()
    try:
        user = session.execute(
            select(UserPg).where(UserPg.email == email)
        ).scalar_one()
        return decrypt_secret(user.totp_secret)
    finally:
        session.close()



# ---------------------------------------------------------------------------
# 7. Audit log hygiene (rule 7): no emails, no tokens
# ---------------------------------------------------------------------------

def test_audit_log_contains_no_pii_or_tokens(client, session_factory):
    _register(client, "audit@synthetic.example.com")
    tokens = _login(client, "audit@synthetic.example.com").json()
    client.get("/auth/me", headers=_auth_header(tokens))

    session = session_factory()
    try:
        rows = session.execute(select(AuditLogPg)).scalars().all()
    finally:
        session.close()
    assert rows, "expected audit rows for register/login"
    for row in rows:
        blob = " ".join(
            str(getattr(row, col) or "")
            for col in ("actor_id", "action", "resource_type", "outcome")
        )
        assert "audit@synthetic.example.com" not in blob
        assert tokens["access_token"] not in blob
        assert tokens["refresh_token"] not in blob


# ---------------------------------------------------------------------------
# 8. Password storage hygiene
# ---------------------------------------------------------------------------

def test_password_is_stored_as_argon2_hash(client, session_factory):
    _register(client, "storage@synthetic.example.com")
    session = session_factory()
    try:
        user = session.execute(
            select(UserPg).where(UserPg.email == "storage@synthetic.example.com")
        ).scalar_one()
        assert user.password_hash.startswith("$argon2")
        assert PASSWORD not in user.password_hash
    finally:
        session.close()



# ---------------------------------------------------------------------------
# 9. Admin user provisioning (POST /auth/admin/users)
# ---------------------------------------------------------------------------

def _provision_admin(session_factory, email: str = "root-admin@synthetic.example.com") -> dict:
    """Create an admin directly in the DB and return fully-authenticated headers."""
    from app.auth.passwords import hash_password
    from app.auth.tokens import create_access_token

    session = session_factory()
    try:
        user = UserPg(
            email=email,
            password_hash=hash_password(PASSWORD),
            role="admin",
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        token, _ = create_access_token(user.id, "admin", mfa_ok=True)
        return {"Authorization": f"Bearer {token}"}
    finally:
        session.close()


def test_admin_provisions_reviewer_account(client, session_factory):
    admin_headers = _provision_admin(session_factory)
    response = client.post(
        "/auth/admin/users",
        headers=admin_headers,
        json={
            "email": "provisioned@synthetic.example.com",
            "password": PASSWORD,
            "role": "reviewer",
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["role"] == "reviewer"
    assert body["email"] == "provisioned@synthetic.example.com"

    # The provisioned reviewer can log in with the password they were given.
    login = _login(client, "provisioned@synthetic.example.com")
    assert login.status_code == 200
    assert login.json()["user"]["role"] == "reviewer"


def test_admin_provisions_admin_account(client, session_factory):
    admin_headers = _provision_admin(session_factory, "first-admin@synthetic.example.com")
    response = client.post(
        "/auth/admin/users",
        headers=admin_headers,
        json={
            "email": "second-admin@synthetic.example.com",
            "password": PASSWORD,
            "role": "admin",
        },
    )
    assert response.status_code == 201
    assert response.json()["role"] == "admin"


def test_admin_provisioning_requires_authentication(client):
    response = client.post(
        "/auth/admin/users",
        json={"email": "x@synthetic.example.com", "password": PASSWORD,
              "role": "reviewer"},
    )
    assert response.status_code == 401


def test_reviewer_cannot_provision_users(client, session_factory):
    _provision_reviewer(client, session_factory, "sneaky-reviewer@synthetic.example.com")
    tokens = _login(client, "sneaky-reviewer@synthetic.example.com").json()
    provisioning = _enroll_mfa(client, tokens)
    tokens = _login(
        client, "sneaky-reviewer@synthetic.example.com",
        totp_code=_totp_code(provisioning),
    ).json()
    response = client.post(
        "/auth/admin/users",
        headers=_auth_header(tokens),
        json={"email": "victim@synthetic.example.com", "password": PASSWORD,
              "role": "admin"},
    )
    assert response.status_code == 403


def test_citizen_cannot_provision_users(client, session_factory):
    _register(client, "ordinary-citizen@synthetic.example.com")
    tokens = _login(client, "ordinary-citizen@synthetic.example.com").json()
    response = client.post(
        "/auth/admin/users",
        headers=_auth_header(tokens),
        json={"email": "escalate@synthetic.example.com", "password": PASSWORD,
              "role": "admin"},
    )
    assert response.status_code == 403

def test_admin_provisioning_rejects_weak_password(client, session_factory):
    admin_headers = _provision_admin(session_factory)
    response = client.post(
        "/auth/admin/users",
        headers=admin_headers,
        json={"email": "weak-pw@synthetic.example.com", "password": "short1",
              "role": "reviewer"},
    )
    assert response.status_code == 400


def test_admin_provisioning_rejects_citizen_role(client, session_factory):
    """The provisioning endpoint only elevates; citizens go through /auth/register."""
    admin_headers = _provision_admin(session_factory)
    response = client.post(
        "/auth/admin/users",
        headers=admin_headers,
        json={"email": "nope@synthetic.example.com", "password": PASSWORD,
              "role": "citizen"},
    )
    assert response.status_code == 422  # Literal["reviewer", "admin"] fails


def test_admin_provisioning_rejects_duplicate_email(client, session_factory):
    admin_headers = _provision_admin(session_factory)
    payload = {"email": "dup-provision@synthetic.example.com",
               "password": PASSWORD, "role": "reviewer"}
    first = client.post("/auth/admin/users", headers=admin_headers, json=payload)
    assert first.status_code == 201
    again = client.post("/auth/admin/users", headers=admin_headers, json=payload)
    assert again.status_code == 409


def test_provisioned_account_needs_mfa_before_privileged_use(client, session_factory):
    """A provisioned reviewer's password-only token is bootstrap-only."""
    admin_headers = _provision_admin(session_factory)
    client.post(
        "/auth/admin/users",
        headers=admin_headers,
        json={"email": "fresh-reviewer@synthetic.example.com",
              "password": PASSWORD, "role": "reviewer"},
    )
    tokens = _login(client, "fresh-reviewer@synthetic.example.com").json()
    assert tokens["mfa_ok"] is False
    # Bootstrap tokens cannot reach authenticated endpoints for reviewers.
    me = client.get("/auth/me", headers=_auth_header(tokens))
    assert me.status_code == 401


# ---------------------------------------------------------------------------
# 10. Legacy SQLite auth endpoints are gone
# ---------------------------------------------------------------------------

def test_legacy_signup_endpoint_is_removed(client):
    response = client.post(
        "/auth/signup",
        json={"email": "legacy@synthetic.example.com", "password": PASSWORD},
    )
    assert response.status_code == 404  # /auth/signup no longer exists


def test_legacy_signin_endpoint_is_removed(client):
    response = client.post(
        "/auth/signin",
        json={"email": "legacy@synthetic.example.com", "password": PASSWORD},
    )
    assert response.status_code == 404


def test_legacy_profile_endpoint_is_removed(client):
    response = client.post(
        "/auth/profile", json={"name": "Legacy", "dob": "1990-01-01"}
    )
    assert response.status_code == 404


