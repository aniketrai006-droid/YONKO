from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.auth_routes import router as auth_router
from app.api.case_routes import router as case_router

app = FastAPI()
app.include_router(auth_router)
app.include_router(case_router)
client = TestClient(app)


def _signup(email: str, password: str = "password123"):
    return client.post("/auth/signup", json={"email": email, "password": password})


def _auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_signin_without_signup_is_rejected():
    response = client.post(
        "/auth/signin",
        json={"email": "new.reviewer@department.gov.in", "password": "password123"},
    )
    assert response.status_code == 401
    assert "sign up" in response.json()["detail"].lower()


def test_signup_stores_account_and_wrong_password_fails():
    created = _signup("officer@department.gov.in")
    assert created.status_code == 200
    assert created.json()["email"] == "officer@department.gov.in"
    assert created.json()["token"]

    wrong = client.post(
        "/auth/signin",
        json={"email": "officer@department.gov.in", "password": "wrongpass"},
    )
    assert wrong.status_code == 401
    assert "incorrect" in wrong.json()["detail"].lower()

    ok = client.post(
        "/auth/signin",
        json={"email": "officer@department.gov.in", "password": "password123"},
    )
    assert ok.status_code == 200
    assert ok.json()["token"]


def test_duplicate_signup_is_rejected():
    _signup("repeat@department.gov.in")
    again = _signup("repeat@department.gov.in")
    assert again.status_code == 409


def test_cases_are_isolated_per_reviewer():
    first = _signup("piyush.owner@department.gov.in").json()
    second = _signup("other.reviewer@department.gov.in").json()

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


def test_brute_force_lockout_returns_429():
    """Fire MAX_FAILED_ATTEMPTS wrong passwords; the next attempt must return 429."""
    from app.security import MAX_FAILED_ATTEMPTS

    email = "lockout.test@department.gov.in"
    _signup(email, password="correct-password123")

    # Submit wrong passwords up to the threshold; each must be ≥8 chars to pass
    # the format-validation layer and actually reach the DB lockout counter.
    for i in range(MAX_FAILED_ATTEMPTS):
        resp = client.post(
            "/auth/signin",
            json={"email": email, "password": "wrongpassword123"},
        )
        # Each attempt before the account is locked returns 401
        assert resp.status_code == 401, (
            f"Expected 401 on attempt {i + 1}, got {resp.status_code}"
        )

    # The account is now locked — even a correct password must be rejected with 429
    locked_resp = client.post(
        "/auth/signin",
        json={"email": email, "password": "correct-password123"},
    )
    assert locked_resp.status_code == 429, (
        f"Expected 429 after {MAX_FAILED_ATTEMPTS} failed attempts, got {locked_resp.status_code}"
    )
