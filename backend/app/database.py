"""
Sync SQLAlchemy 2.x session factory for YONKO's PostgreSQL database.

Security: this module imports settings from app.config — never from app.db
(the SQLite case-store helper). The two database layers are intentionally
isolated to avoid circular imports.

Row-Level Security context: set_rls_context() stores the *verified* JWT
subject (user id + role) on the session and applies it to the current
transaction with SET LOCAL. An after_begin listener re-applies the GUCs
whenever a new transaction starts on that session (e.g. after a commit in
the middle of a request), because SET LOCAL values die with their
transaction. On SQLite (dev/tests) the calls are no-ops.

Why sync (not async)?
All existing FastAPI routes in this project use plain `def` (synchronous)
handlers. Introducing AsyncSession would require wrapping every route in
async def and adding an async event loop, which is out of scope and would
risk regressions in case_routes.py and the JWT auth routes. Sync SQLAlchemy
with psycopg2 is the correct choice here.
"""

from __future__ import annotations

import uuid
from collections.abc import Generator

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings

# pool_pre_ping=True causes SQLAlchemy to test the connection before using it,
# preventing stale-connection errors after a Postgres restart or idle timeout.
engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True)

# autocommit=False: transactions must be explicitly committed — prevents
# accidental partial writes from being auto-committed on session close.
# autoflush=False: prevents implicit flushes that could surface constraint
# violations at unexpected points during request processing.
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
)

# GUC names read by the RLS policies in app.security.rls.
_GUC_USER_ID = "app.current_user_id"
_GUC_ROLE = "app.current_role"

# Valid values for app.current_role — anything else fails closed in the
# policies, but we refuse to set an unknown role outright.
_VALID_RLS_ROLES = {"citizen", "reviewer", "admin"}

_SET_GUCS_SQL = text(
    "SELECT set_config(:uid_key, :uid_value, true), "
    "set_config(:role_key, :role_value, true)"
)


def _apply_rls_gucs(db: Session) -> None:
    """Apply the session's stored RLS context to the current transaction."""
    context = db.info.get("rls_context")
    if context is None:
        return
    if db.get_bind().dialect.name != "postgresql":
        return  # SQLite has no RLS/GUCs — no-op in dev and unit tests
    db.execute(_SET_GUCS_SQL, {
        "uid_key": _GUC_USER_ID,
        "uid_value": context["user_id"],
        "role_key": _GUC_ROLE,
        "role_value": context["role"],
    })


def set_rls_context(db: Session, user_id: uuid.UUID, role: str) -> None:
    """Bind the RLS identity (verified JWT subject) to this session.

    Call this ONLY with values loaded from the authenticated UserPg row
    (see app.auth.deps.get_current_user) — never from client input. The
    GUCs are set with SET LOCAL, so they are scoped to the current
    transaction; the after_begin listener re-applies them for any later
    transaction on the same session.
    """
    if role not in _VALID_RLS_ROLES:
        raise ValueError(f"Invalid RLS role: {role!r}")
    db.info["rls_context"] = {"user_id": str(user_id), "role": role}
    _apply_rls_gucs(db)


@event.listens_for(Session, "after_begin")
def _reapply_rls_context(db: Session, transaction, connection) -> None:
    """Re-apply SET LOCAL GUCs at the start of every new transaction.

    SET LOCAL values are dropped when their transaction commits or rolls
    back. Routes commit mid-request (e.g. audit writes), so without this
    listener the next transaction on the same session would run with no
    identity — and RLS would fail closed, hiding the user's own rows.
    """
    try:
        _apply_rls_gucs(db)
    except Exception:  # pragma: no cover - defensive; never break begin
        pass


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that yields a database session and guarantees cleanup.

    Usage:
        @router.get("/example")
        def example(db: Session = Depends(get_db)):
            ...

    The session is always closed in the finally block, even if the route
    raises an exception. Commit/rollback decisions are left to the caller
    so that route handlers can batch multiple operations in one transaction.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
