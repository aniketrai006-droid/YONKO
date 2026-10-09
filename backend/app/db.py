"""SQLite persistence for the reviewer dashboard's case store.

This is NOT an authentication store. The legacy users/sessions tables and
the SQLite audit log were removed together with the SQLite session auth
system (auth_routes.py); all authentication now lives in PostgreSQL via
the JWT system (app.auth + app.models). The `cases` table keeps its JSON
payloads here because the dashboard predates the PostgreSQL layer.

Security: connection settings favour durability-over-convenience pragmas,
the DB file is chmod-ed owner-only on POSIX, and queries are parameterised
(SQLAlchemy is not used for this legacy store — steering rule 3 allows
parameterised sqlite3 usage).
"""

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


def _migrate_legacy_cases_schema(connection: sqlite3.Connection) -> None:
    """Rebuild `cases` without its foreign key to the removed legacy
    `users` table.

    Existing developer databases were created when `cases.owner_email`
    referenced `users(email)`. With the users table gone, that foreign key
    would make every INSERT fail with "foreign key mismatch". SQLite cannot
    drop a foreign key in place, so the table is rebuilt: create the new
    schema, copy the rows, drop the old table.
    """
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'cases'"
    ).fetchone()
    if row is None or "REFERENCES users" not in (row["sql"] or ""):
        return  # fresh DB or already migrated
    connection.executescript(
        """
        CREATE TABLE cases_migrated (
            id          TEXT NOT NULL,
            owner_email TEXT NOT NULL,
            payload     TEXT NOT NULL,
            updated_at  TEXT NOT NULL,
            PRIMARY KEY (id, owner_email)
        );
        INSERT INTO cases_migrated (id, owner_email, payload, updated_at)
            SELECT id, owner_email, payload, updated_at FROM cases;
        DROP TABLE cases;
        ALTER TABLE cases_migrated RENAME TO cases;
        CREATE INDEX IF NOT EXISTS idx_cases_owner ON cases(owner_email);
        """
    )


def _init(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")   # safer concurrent writes
    connection.execute("PRAGMA synchronous = NORMAL")  # balance durability vs speed
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS cases (
            id          TEXT NOT NULL,
            owner_email TEXT NOT NULL,
            payload     TEXT NOT NULL,
            updated_at  TEXT NOT NULL,
            PRIMARY KEY (id, owner_email)
        );

        CREATE INDEX IF NOT EXISTS idx_cases_owner ON cases(owner_email);
        """
    )
    _migrate_legacy_cases_schema(connection)


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
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
