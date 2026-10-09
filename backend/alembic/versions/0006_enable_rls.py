"""enable_rls

Revision ID: 0006
Revises: 0005
Create Date: 2025-01-06 00:00:00.000000

Creates the app_user / migration_user database roles, applies the
least-privilege grants, and enables PostgreSQL Row-Level Security on
bundles, documents, findings_pg and review_decisions.

PostgreSQL-only: on SQLite (local dev / default test runs) this migration
is a no-op — SQLite has no roles or RLS. The policies themselves live in
app.security.rls so the real-Postgres test suite verifies exactly the SQL
this migration applies.

Passwords come from the environment (never hardcoded, steering rule 3):
  APP_DB_PASSWORD       — password for app_user (the API's login)
  MIGRATION_USER_PASSWORD — password for migration_user (alembic's login)
If either is missing the migration fails loudly rather than creating a
role with an empty password.
"""

from __future__ import annotations

import os

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return  # SQLite dev/test: no roles or RLS available

    app_password = os.environ.get("APP_DB_PASSWORD", "")
    migration_password = os.environ.get("MIGRATION_USER_PASSWORD", "")
    if not app_password or not migration_password:
        raise RuntimeError(
            "APP_DB_PASSWORD and MIGRATION_USER_PASSWORD must be set in the "
            "environment before running migration 0006 on PostgreSQL."
        )

    # Imported here (not at module level) so SQLite runs never pull in
    # the RLS helpers.
    from app.security.rls import setup_full_rls

    setup_full_rls(bind, app_password, migration_password)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    from app.security.rls import RLS_TABLES

    for table in RLS_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {table}_access ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    # Grants are intentionally NOT revoked in the downgrade — removing
    # privileges is an operational action, not something to automate away.
