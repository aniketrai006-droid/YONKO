"""
Sync SQLAlchemy 2.x session factory for YONKO's PostgreSQL database.

Security: this module imports settings from app.config — never from app.db
(the existing SQLite helper). The two database layers are intentionally
isolated to avoid circular imports and to keep the legacy SQLite auth system
independent of the new ORM layer.

Why sync (not async)?
All existing FastAPI routes in this project use plain `def` (synchronous)
handlers. Introducing AsyncSession would require wrapping every route in
async def and adding an async event loop, which is out of scope and would
risk regressions in case_routes.py and the JWT auth routes. Sync SQLAlchemy
with psycopg2 is the correct choice here.
"""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
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
