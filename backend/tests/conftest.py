import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setenv("SAMANVAY_DB_PATH", str(tmp_path / "samanvay.sqlite"))


@pytest.fixture()
def api_db(monkeypatch):
    """In-memory SQLite session factory wired into app.database.

    Patches app.database.engine and SessionLocal so both the FastAPI
    get_db dependency and any direct SessionLocal use (e.g. the legacy
    auth bridge) hit the same isolated database during the test.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    import app.database as db_module
    from app.models import Base

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(
        bind=engine, autocommit=False, autoflush=False
    )
    monkeypatch.setattr(db_module, "engine", engine)
    monkeypatch.setattr(db_module, "SessionLocal", TestSession)
    return TestSession


@pytest.fixture()
def auth_headers(api_db):
    """Factory: create a synthetic user with the given role and return
    Authorization headers carrying a valid (mfa_ok) access token.

    Tokens are minted directly via create_access_token to keep tests fast;
    the full login/MFA flows are covered in test_auth_jwt.py.
    """
    from app.auth.tokens import create_access_token
    from app.models import UserPg

    def make(role: str = "citizen", email: str | None = None) -> dict:
        session = api_db()
        try:
            user = UserPg(
                email=email
                or f"{role}-{uuid.uuid4().hex[:8]}@synthetic.example.com",
                # Never a usable hash — these users authenticate by token only.
                password_hash="not-a-real-hash",
                role=role,
            )
            session.add(user)
            session.commit()
            session.refresh(user)
            token, _ = create_access_token(user.id, role, mfa_ok=True)
            return {"Authorization": f"Bearer {token}"}
        finally:
            session.close()

    return make

