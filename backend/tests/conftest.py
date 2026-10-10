import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setenv("SAMANVAY_DB_PATH", str(tmp_path / "samanvay.sqlite"))
    monkeypatch.delenv("DATABASE_URL", raising=False)
    # Rate-limit and lockout state is process-local; reset it so tests do
    # not bleed into each other.
    from app.ratelimit import limiter, login_failures

    limiter.reset()
    login_failures.reset()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    return TestClient(app)


@pytest.fixture
def auth_headers(client):
    """Sign up a unique reviewer and return their Authorization header."""
    email = f"reviewer-{uuid.uuid4().hex[:10]}@department.gov.in"
    response = client.post(
        "/auth/signup", json={"email": email, "password": "password123"})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}
