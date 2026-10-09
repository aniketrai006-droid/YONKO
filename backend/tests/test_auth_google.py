"""Google sign-in contract tests. Google's network call is stubbed out."""

from __future__ import annotations

import time

from fastapi.testclient import TestClient

from app.auth import google as google_auth
from app.auth.google import GoogleAuthError
from app.main import app

client = TestClient(app)

CLIENT_ID = "1234567890-abc.apps.googleusercontent.com"
CREDENTIAL = "header.payload.signature"


def _claims(**overrides: object) -> dict[str, object]:
    claims: dict[str, object] = {
        "aud": CLIENT_ID,
        "iss": "accounts.google.com",
        "email_verified": "true",
        "exp": int(time.time()) + 300,
        "email": "reviewer@department.gov.in",
        "name": "Reviewer One",
        "picture": "https://example.com/avatar.png",
        "sub": "google-sub-1",
    }
    claims.update(overrides)
    return claims


def _stub_google(monkeypatch, claims: dict[str, object] | None = None,
                 error: GoogleAuthError | None = None) -> None:
    monkeypatch.setenv("GOOGLE_CLIENT_ID", CLIENT_ID)

    def fetch(credential: str) -> dict[str, object]:
        if error is not None:
            raise error
        if credential != CREDENTIAL:
            raise GoogleAuthError("Google rejected the credential.")
        return claims or _claims()

    monkeypatch.setattr(google_auth, "_fetch_claims", fetch)


def _sign_in(credential: str = CREDENTIAL):
    return client.post("/auth/google", json={"credential": credential})


def test_google_sign_in_issues_session_and_me_accepts_it(monkeypatch):
    _stub_google(monkeypatch)

    response = _sign_in()
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["user"] == {
        "sub": "google-sub-1",
        "email": "reviewer@department.gov.in",
        "name": "Reviewer One",
        "picture": "https://example.com/avatar.png",
    }

    me = client.get("/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200, me.text
    assert me.json()["user"]["email"] == "reviewer@department.gov.in"


def test_google_sign_in_accepts_verified_google_claims(monkeypatch):
    _stub_google(monkeypatch, claims=_claims(email="New.Reviewer@Example.gov.in",
                                             email_verified=True))

    body = _sign_in().json()
    assert body["user"]["email"] == "new.reviewer@example.gov.in"


def test_google_sign_in_rejects_wrong_audience(monkeypatch):
    _stub_google(monkeypatch, claims=_claims(aud="other-app.apps.googleusercontent.com"))

    response = _sign_in()
    assert response.status_code == 401
    assert "different application" in response.json()["detail"]


def test_google_sign_in_rejects_expired_credential(monkeypatch):
    _stub_google(monkeypatch, claims=_claims(exp=int(time.time()) - 5))

    response = _sign_in()
    assert response.status_code == 401
    assert "expired" in response.json()["detail"]


def test_google_sign_in_rejects_unverified_email(monkeypatch):
    _stub_google(monkeypatch, claims=_claims(email_verified="false"))

    response = _sign_in()
    assert response.status_code == 401
    assert "not verified" in response.json()["detail"]


def test_google_sign_in_requires_server_client_id(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)

    def fetch(credential: str) -> dict[str, object]:
        raise AssertionError("Google must not be called before configuration is checked")

    monkeypatch.setattr(google_auth, "_fetch_claims", fetch)

    response = _sign_in()
    assert response.status_code == 401
    assert "not configured" in response.json()["detail"]


def test_google_sign_in_rejects_empty_credential(monkeypatch):
    _stub_google(monkeypatch)

    response = _sign_in("")
    assert response.status_code == 401
    assert "missing" in response.json()["detail"]


def test_google_sign_in_surfaces_google_rejection(monkeypatch):
    _stub_google(monkeypatch, error=GoogleAuthError("Google rejected the credential."))

    response = _sign_in()
    assert response.status_code == 401
    assert response.json()["detail"] == "Google rejected the credential."


def test_me_requires_a_valid_session_token():
    assert client.get("/auth/me").status_code == 401
    assert client.get("/auth/me", headers={"Authorization": "Token abc"}).status_code == 401
    assert client.get("/auth/me", headers={"Authorization": "Bearer forged.token"}).status_code == 401


def test_expired_session_token_is_refused(monkeypatch):
    monkeypatch.setenv("YONKO_SESSION_SECRET", "test-secret")
    token = google_auth._sign({
        "sub": "google-sub-1",
        "email": "reviewer@department.gov.in",
        "name": "Reviewer One",
        "picture": "",
        "iat": int(time.time()) - 600,
        "exp": int(time.time()) - 10,
    })

    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert "expired" in response.json()["detail"]


def test_session_token_tampering_is_refused(monkeypatch):
    monkeypatch.setenv("YONKO_SESSION_SECRET", "test-secret")
    token = google_auth.issue_session({
        "sub": "google-sub-1",
        "email": "reviewer@department.gov.in",
        "name": "Reviewer One",
        "picture": "",
    })
    forged = token[:-2] + ("AA" if not token.endswith("AA") else "BB")

    response = client.get("/auth/me", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401
