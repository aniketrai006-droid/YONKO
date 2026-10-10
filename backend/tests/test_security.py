"""Security test suite - the evidence pack for judges.

Each test demonstrates one concrete attack and proves the API resists it:
authentication bypass, SQL injection, path traversal, content spoofing,
brute force, session theft from the database, XSS payloads, and more.

Run with:  pytest tests/test_security.py -v
"""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from app.main import app
from app.security import hash_session_token

client = TestClient(app)

SIGNUP_EMAIL = f"security-{uuid.uuid4().hex[:8]}@department.gov.in"
SIGNUP_PASSWORD = "SecurePass1"


def _signup(email: str = SIGNUP_EMAIL, password: str = SIGNUP_PASSWORD):
    return client.post(
        "/auth/signup", json={"email": email, "password": password})


def _signin(email: str = SIGNUP_EMAIL, password: str = SIGNUP_PASSWORD):
    return client.post(
        "/auth/signin", json={"email": email, "password": password})


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _png_bytes() -> bytes:
    """Minimal valid PNG (1x1 transparent)."""
    import base64

    return base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"
        "YPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
    )


# ---------------------------------------------------------------------------
# 1. Authentication and session security
# ---------------------------------------------------------------------------

def test_analyze_requires_authentication():
    """Anonymous users cannot burn OCR compute or read document data."""
    files = [("files", ("a.png", _png_bytes(), "image/png")),
             ("files", ("b.png", _png_bytes(), "image/png"))]
    response = client.post("/analyze", files=files)
    assert response.status_code == 401


def test_forged_session_token_is_rejected():
    """A guessed/bruteforced token string grants nothing."""
    response = client.get("/cases", headers=_auth("a" * 43))
    assert response.status_code == 401


def test_session_token_is_stored_hashed_not_raw():
    """The database never contains the raw bearer token."""
    import sqlite3

    from app.db import db_path

    token = _signup().json()["token"]
    connection = sqlite3.connect(db_path())
    try:
        rows = connection.execute(
            "SELECT token_hash FROM sessions").fetchall()
    finally:
        connection.close()
    assert rows, "a session row must exist after signup"
    stored = {row[0] for row in rows}
    assert token not in stored, "raw session token leaked into the database!"
    assert hash_session_token(token) in stored


def test_password_is_never_stored_in_plaintext():
    import sqlite3

    from app.db import db_path

    _signup()
    connection = sqlite3.connect(db_path())
    try:
        (stored,) = connection.execute(
            "SELECT password_hash FROM users WHERE email = ?",
            (SIGNUP_EMAIL,)).fetchone()
    finally:
        connection.close()
    assert SIGNUP_PASSWORD not in stored
    # PBKDF2 format: salt_hex $ digest_hex
    salt, digest = stored.split("$")
    assert len(bytes.fromhex(salt)) == 16
    assert len(digest) >= 64


def test_signin_does_not_reveal_whether_account_exists():
    """Unknown email and wrong password return the identical error."""
    _signup()
    unknown = _signin("nobody-here@department.gov.in")
    wrong = _signin(SIGNUP_EMAIL, "WrongPass9")
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json()["detail"] == wrong.json()["detail"]


def test_expired_session_is_rejected():
    """A session past its TTL no longer authenticates."""
    import sqlite3

    from app.db import db_path

    token = _signup().json()["token"]
    connection = sqlite3.connect(db_path())
    try:
        connection.execute(
            "UPDATE sessions SET expires_at = '2000-01-01T00:00:00+00:00'")
        connection.commit()
    finally:
        connection.close()
    response = client.get("/cases", headers=_auth(token))
    assert response.status_code == 401


def test_logout_invalidates_the_token():
    token = _signup().json()["token"]
    assert client.post("/auth/logout", headers=_auth(token)).status_code == 200
    assert client.get("/cases", headers=_auth(token)).status_code == 401


def test_weak_passwords_are_rejected():
    for bad in ["short1", "alllettershere", "12345678", "        "]:
        response = _signup(f"weak-{uuid.uuid4().hex[:6]}@department.gov.in", bad)
        assert response.status_code == 400, f"accepted weak password: {bad!r}"

# ---------------------------------------------------------------------------
# 2. Brute force and abuse
# ---------------------------------------------------------------------------

def test_brute_force_lockout_after_repeated_failures(monkeypatch):
    """Five wrong passwords lock the account even for the right one."""
    monkeypatch.setenv("AUTH_MAX_FAILURES", "5")
    _signup()
    for _ in range(5):
        _signin(SIGNUP_EMAIL, "WrongPass9")
    # Now the correct password is also refused while locked.
    response = _signin(SIGNUP_EMAIL, SIGNUP_PASSWORD)
    assert response.status_code == 429
    assert "locked" in response.json()["detail"].lower()
    assert "Retry-After" in response.headers


def test_signin_rate_limit_per_ip(monkeypatch):
    """Rapid attempts from one IP are throttled with 429."""
    monkeypatch.setenv("AUTH_RATE_LIMIT_PER_MINUTE", "8")
    from app.ratelimit import limiter

    limiter.reset()
    codes = []
    for _ in range(12):
        response = _signin(
            f"spray-{uuid.uuid4().hex[:6]}@department.gov.in")
        codes.append(response.status_code)
    assert 429 in codes, "rate limiter did not engage"


# ---------------------------------------------------------------------------
# 3. Injection attacks
# ---------------------------------------------------------------------------

def test_sql_injection_in_signin_is_neutralized():
    """Classic OR-based SQLi lands as a literal email, not executable SQL."""
    injection = "admin' OR '1'='1' --@department.gov.in"
    response = _signin(injection, "whatever1")
    # Either rejected as an invalid email or fails auth - never a 500.
    assert response.status_code in (400, 401)
    assert "syntax" not in response.text.lower()


def test_sql_injection_in_case_creation_cannot_dump_data():
    token = _signup().json()["token"]
    response = client.post(
        "/cases",
        headers=_auth(token),
        json={
            "applicantName": "'; DROP TABLE cases; --",
            "applicationType": "Scholarship'; --",
            "notes": "1' UNION SELECT email, password_hash FROM users --",
        },
    )
    assert response.status_code == 200  # stored as inert text
    # Table still exists and holds exactly the one case.
    listing = client.get("/cases", headers=_auth(token))
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    # A real leak would expose PBKDF2 hashes (hex$sixty-four-hex chars).
    # The words of the payload may echo back as inert text, so look for
    # actual hash material from the users table instead.
    import re

    hash_material = re.compile(r"[0-9a-f]{32}\$[0-9a-f]{64,}")
    assert not hash_material.search(listing.text)


def test_xss_payload_is_stored_inert_and_json_encoded():
    """A <script> payload round-trips as data, served as JSON (not HTML)."""
    token = _signup().json()["token"]
    payload = "<script>alert('xss')</script>"
    created = client.post(
        "/cases",
        headers=_auth(token),
        json={"applicantName": payload, "applicationType": "Housing",
              "notes": payload},
    )
    assert created.status_code == 200
    assert created.headers["content-type"].startswith("application/json")
    fetched = client.get(
        f"/cases/{created.json()['id']}", headers=_auth(token))
    assert fetched.headers["content-type"].startswith("application/json")
    # React renders this as text; the API never returns an HTML document.
    assert "<html" not in fetched.text.lower()

# ---------------------------------------------------------------------------
# 4. IDOR / broken access control
# ---------------------------------------------------------------------------

def test_reviewer_cannot_read_another_reviewers_case():
    owner = _signup(
        f"owner-{uuid.uuid4().hex[:6]}@department.gov.in").json()
    attacker = _signup(
        f"attacker-{uuid.uuid4().hex[:6]}@department.gov.in").json()

    created = client.post(
        "/cases",
        headers=_auth(owner["token"]),
        json={"applicantName": "Confidential Applicant",
              "applicationType": "Scholarship", "notes": "secret notes"},
    )
    case_id = created.json()["id"]

    stolen = client.get(
        f"/cases/{case_id}", headers=_auth(attacker["token"]))
    assert stolen.status_code == 404

    modified = client.patch(
        f"/cases/{case_id}/status",
        headers=_auth(attacker["token"]),
        json={"status": "cleared"},
    )
    assert modified.status_code == 404



# ---------------------------------------------------------------------------
# 5. File upload attacks
# ---------------------------------------------------------------------------

def test_path_traversal_filename_cannot_escape_temp_dir():
    """../../etc/passwd-style names are never used as filesystem paths."""
    token = _signup().json()["token"]
    png = _png_bytes()
    evil_name = "..\\..\\..\\windows\\system32\\evil.png"
    files = [("files", (evil_name, png, "image/png")),
             ("files", ("normal.png", png, "image/png"))]
    response = client.post("/analyze", files=files, headers=_auth(token))
    # The file is accepted or rejected by content rules, but never written
    # outside the temp directory; a 200 here is fine because the backend
    # renames every upload to upload_NN.png.
    assert response.status_code in (200, 400)
    from pathlib import Path
    assert not Path("windows").exists()
    assert not Path("evil.png").exists()


def test_content_spoofing_rejected_fake_png():
    """A script file renamed to .png fails magic-byte validation."""
    token = _signup().json()["token"]
    fake = b"<" + b"?php system($_GET['cmd']); ?" + b"> fake image data"
    files = [("files", ("payload.png", fake, "image/png")),
             ("files", ("ok.png", _png_bytes(), "image/png"))]
    response = client.post("/analyze", files=files, headers=_auth(token))
    assert response.status_code == 400
    assert "does not match its file type" in response.json()["detail"]


def test_content_spoofing_rejected_fake_pdf():
    token = _signup().json()["token"]
    fake = b"MZ\x90\x00 this is an executable pretending to be a pdf"
    files = [("files", ("dropper.pdf", fake, "application/pdf")),
             ("files", ("ok.png", _png_bytes(), "image/png"))]
    response = client.post("/analyze", files=files, headers=_auth(token))
    assert response.status_code == 400


def test_oversized_upload_is_rejected():
    """Files above MAX_UPLOAD_BYTES get a 413, not an OOM."""
    token = _signup().json()["token"]
    from app.api.routes import MAX_UPLOAD_BYTES

    big = _png_bytes() + b"\x00" * (MAX_UPLOAD_BYTES + 1024)
    files = [("files", ("big.png", big, "image/png")),
             ("files", ("ok.png", _png_bytes(), "image/png"))]
    response = client.post("/analyze", files=files, headers=_auth(token))
    assert response.status_code == 413


def test_disallowed_extension_is_rejected():
    token = _signup().json()["token"]
    files = [("files", ("run.exe", b"MZ...", "application/octet-stream")),
             ("files", ("ok.png", _png_bytes(), "image/png"))]
    response = client.post("/analyze", files=files, headers=_auth(token))
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# 6. Transport and browser hardening
# ---------------------------------------------------------------------------

def test_security_headers_present():
    response = client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert "Referrer-Policy" in response.headers


def test_cors_rejects_unknown_origins():
    """A malicious site cannot call the API with a browser session."""
    response = client.options(
        "/api/info",
        headers={
            "Origin": "https://evil.example.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert "access-control-allow-origin" not in response.headers


def test_cors_allows_the_configured_frontend():
    response = client.options(
        "/api/info",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.headers.get("access-control-allow-origin") == \
        "http://localhost:5173"


def test_audit_log_records_security_events():
    """Sign-ins (successful and failed) land in the audit trail."""
    import sqlite3

    from app.db import db_path

    email = f"audit-{uuid.uuid4().hex[:6]}@department.gov.in"
    _signup(email)
    _signin(email, "WrongPass9")
    connection = sqlite3.connect(db_path())
    try:
        events = [row[0] for row in connection.execute(
            "SELECT event FROM audit_log WHERE email = ?", (email,))]
    finally:
        connection.close()
    assert "signup.success" in events
    assert "signin.failed" in events


def test_cases_require_authentication():
    response = client.get("/cases")
    assert response.status_code == 401

