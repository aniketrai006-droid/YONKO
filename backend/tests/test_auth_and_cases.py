"""Per-reviewer case isolation over the JWT-authenticated /cases endpoints.

The legacy SQLite session tests that used to live here were removed together
with auth_routes.py; account lifecycle (register/login/lockout/MFA) is now
covered by test_auth_jwt.py, and role-gated endpoints by
test_review_decisions.py. These tests keep the /cases isolation contract.
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.case_routes import router as case_router

app = FastAPI()
app.include_router(case_router)
client = TestClient(app)


def _auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _login(api_db, email: str, role: str = "reviewer") -> dict:
    """Create a synthetic user with the given role and return tokens via
    the real /auth/login endpoint (Argon2 + JWT, no MFA enrolled yet —
    bootstrap tokens are rejected by get_current_user for reviewers, so
    we mint a fully-authenticated token directly instead)."""
    from app.auth.passwords import hash_password
    from app.auth.tokens import create_access_token
    from app.models import UserPg

    session = api_db()
    try:
        user = UserPg(
            email=email,
            password_hash=hash_password("Synthetic-Passw0rd"),
            role=role,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        token, _ = create_access_token(user.id, role, mfa_ok=True)
        return {"email": user.email, "token": token}
    finally:
        session.close()


def test_cases_require_authentication():
    assert client.get("/cases").status_code == 401
    assert client.post("/cases", json={"applicantName": "X",
                                       "applicationType": "Y"}).status_code == 401


def test_cases_are_isolated_per_reviewer(api_db):
    first = _login(api_db, "owner-a@synthetic.example.com")
    second = _login(api_db, "owner-b@synthetic.example.com")

    created = client.post(
        "/cases",
        headers=_auth_header(first["token"]),
        json={"applicantName": "Piyush", "applicationType": "Scholarship", "notes": ""},
    )
    assert created.status_code == 200
    case_id = created.json()["id"]

    owner_list = client.get("/cases", headers=_auth_header(first["token"]))
    assert owner_list.status_code == 200
    assert owner_list.json()["total"] == 1
    assert owner_list.json()["items"][0]["applicantName"] == "Piyush"

    other_list = client.get("/cases", headers=_auth_header(second["token"]))
    assert other_list.status_code == 200
    assert other_list.json()["total"] == 0
    assert other_list.json()["items"] == []

    leaked = client.get(f"/cases/{case_id}", headers=_auth_header(second["token"]))
    assert leaked.status_code == 404


def test_invalid_token_rejected():
    response = client.get(
        "/cases", headers=_auth_header("not.a.real.token")
    )
    assert response.status_code == 401

