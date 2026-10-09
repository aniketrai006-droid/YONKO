"""SQLite persistence for reviewer accounts, sessions, cases, and audit logs."""

from __future__ import annotations

import os
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).resolve().parents[1] / "data" / "samanvay.sqlite"


def db_path() -> Path:
    override = os.getenv("SAMANVAY_DB_PATH")
    return Path(override) if override else DEFAULT_DB_PATH


def _secure_db_file(path: Path) -> None:
    """Restrict DB file permissions to owner-only on POSIX systems."""
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass  # Windows — silently skip


def _init(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")   # safer concurrent writes
    connection.execute("PRAGMA synchronous = NORMAL")  # balance durability vs speed
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            email           TEXT PRIMARY KEY,
            password_hash   TEXT NOT NULL,
            name            TEXT NOT NULL DEFAULT '',
            dob             TEXT NOT NULL DEFAULT '',
            created_at      TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until    TEXT
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token       TEXT PRIMARY KEY,
            email       TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            expires_at  TEXT NOT NULL,
            FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS cases (
            id          TEXT NOT NULL,
            owner_email TEXT NOT NULL,
            payload     TEXT NOT NULL,
            updated_at  TEXT NOT NULL,
            PRIMARY KEY (id, owner_email),
            FOREIGN KEY (owner_email) REFERENCES users(email) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT    NOT NULL,
            -- Security: actor_id is an opaque HMAC-SHA256 of the email (hex, first 16 chars).
            -- Never store raw email or other PII here. See docs/SECURITY.md.
            actor_id    TEXT,
            action      TEXT    NOT NULL,
            detail      TEXT,
            ip          TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_sessions_email ON sessions(email);
        CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
        CREATE INDEX IF NOT EXISTS idx_cases_owner ON cases(owner_email);
        CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id);
        CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
        """
    )


@contextmanager
def get_connection():
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        _init(connection)
        _secure_db_file(path)
        yield connection
        connection.commit()
    except Exception as exc:
        # Security: HTTPException is an intentional application response (e.g. 401,
        # 429 from the lockout path).  Commit any pending writes (like the
        # failed_attempts counter increment) before re-raising so that security
        # counters are not silently discarded.  All other exceptions roll back.
        from fastapi import HTTPException
        if isinstance(exc, HTTPException):
            connection.commit()
        else:
            connection.rollback()
        raise
    finally:
        connection.close()


def _opaque_actor_id(email: str | None) -> str | None:
    """Return a short HMAC-SHA256 of email so audit rows are linkable but not PII.

    Security: raw email is never written to audit_log.  The hex digest prefix
    is long enough for linkability within the system but not a reversible lookup.
    """
    if not email:
        return None
    import hashlib, hmac as _hmac
    digest = _hmac.new(b"audit-actor", email.lower().encode(), hashlib.sha256).hexdigest()
    return digest[:16]  # 64-bit prefix — sufficient for linkability, not a full hash


def audit(connection: sqlite3.Connection, email: str | None, action: str,
          detail: str = "", ip: str = "") -> None:
    """Insert a row into audit_log. Call inside an open get_connection() block.

    Security: email is converted to an opaque actor_id before storage so that
    no PII is written to the audit log.  See docs/SECURITY.md.
    """
    from app.security import utc_now  # avoid circular import at module load
    actor_id = _opaque_actor_id(email)
    connection.execute(
        "INSERT INTO audit_log (ts, actor_id, action, detail, ip) VALUES (?, ?, ?, ?, ?)",
        (utc_now(), actor_id, action, detail, ip),
    )


def purge_expired_sessions(connection: sqlite3.Connection) -> None:
    """Remove expired sessions. Call once per login to keep the table tidy."""
    from app.security import utc_now
    connection.execute(
        "DELETE FROM sessions WHERE expires_at < ?", (utc_now(),)
    )
