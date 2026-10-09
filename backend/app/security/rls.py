"""PostgreSQL Row-Level Security (RLS) setup — single source of truth.

The SQL here is executed by Alembic migration 0006 AND by the real-Postgres
RLS test suite, so the policies the DB enforces are always the policies the
tests verify.

Design (steering rule 8 — every security decision explained):

1. Two database roles:
   - `app_user`: what the API connects as. GRANT SELECT/INSERT/UPDATE only
     on the tables the app touches — no DELETE anywhere, no DDL, no
     superuser. The audit log is INSERT-only (no SELECT/UPDATE/DELETE) so
     an attacker who compromises the app credential cannot tamper with or
     exfiltrate the security trail.
   - `migration_user`: owns the schema so `alembic upgrade head` can run
     DDL. It is NOT used by the API at runtime; rotate its password
     independently.

2. RLS is ENABLEd on bundles, documents, findings_pg and
   review_decisions. Policies read two session GUCs set per request with
   SET LOCAL inside the transaction (see app.database.set_rls_context):
     app.current_user_id  — the verified JWT subject (UUID)
     app.current_role     — citizen | reviewer | admin
   The GUCs are only ever set from the authenticated UserPg row loaded by
   get_current_user — never from client-supplied headers or bodies.

3. Policies are fail-closed: if the GUCs are unset (bare psql session as
   app_user), every policy evaluates to NULL → no rows visible. A missing
   identity must never mean "see everything".
"""
from __future__ import annotations

# Tables governed by RLS. audit_log_pg is intentionally NOT listed: it is
# INSERT-only via privileges, which is stronger than row filtering.
RLS_TABLES = ("bundles", "documents", "findings_pg", "review_decisions")

# Privileges app_user receives. DELETE is absent everywhere on purpose —
# the application never deletes rows; retention is an offline operation.
_APP_USER_GRANTS = {
    "users_pg": ("SELECT", "INSERT", "UPDATE"),
    "bundles": ("SELECT", "INSERT", "UPDATE"),
    "documents": ("SELECT", "INSERT", "UPDATE"),
    "findings_pg": ("SELECT", "INSERT", "UPDATE"),
    "review_decisions": ("SELECT", "INSERT", "UPDATE"),
    "refresh_tokens": ("SELECT", "INSERT", "UPDATE"),
    # Audit log: INSERT only. No SELECT (cannot read it back), no UPDATE,
    # no DELETE (cannot tamper). This is the tamper-evidence guarantee.
    "audit_log_pg": ("INSERT",),
}

_CREATE_ROLES_SQL = """
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'migration_user') THEN
        CREATE ROLE migration_user NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN
        CREATE ROLE app_user NOLOGIN;
    END IF;
END
$$;
"""


def setup_roles(connection, app_password: str, migration_password: str) -> None:
    """Create both roles (idempotent) and set their passwords.

    Passwords come from the caller (env vars in production, test fixtures in
    CI) — they are never hardcoded here (steering rule 3). Passwords are set
    via the driver's parameter binding, never interpolated into SQL.
    """
    connection.exec_driver_sql(_CREATE_ROLES_SQL)
    connection.exec_driver_sql("ALTER ROLE migration_user LOGIN")
    connection.exec_driver_sql("ALTER ROLE app_user LOGIN")

    raw = connection.connection.driver_connection
    with raw.cursor() as cursor:
        cursor.execute("ALTER ROLE app_user PASSWORD %s", (app_password,))
        cursor.execute("ALTER ROLE migration_user PASSWORD %s",
                       (migration_password,))

    # Least privilege: app_user may connect and use the public schema but
    # cannot create objects; migration_user may create schema objects.
    # GRANT needs a literal database name — fetched from the server itself
    # (not client input) and double-quoted as an identifier.
    db_name = connection.exec_driver_sql(
        "SELECT current_database()"
    ).scalar_one()
    connection.exec_driver_sql(
        f'GRANT CONNECT ON DATABASE "{db_name}" TO app_user'
    )
    connection.exec_driver_sql("GRANT USAGE ON SCHEMA public TO app_user")
    connection.exec_driver_sql("GRANT USAGE ON SCHEMA public TO migration_user")
    connection.exec_driver_sql("GRANT CREATE ON SCHEMA public TO migration_user")


def grant_app_privileges(connection) -> None:
    """Grant the least-privilege DML set to app_user on every governed table."""
    for table, privileges in _APP_USER_GRANTS.items():
        connection.exec_driver_sql(
            f"GRANT {', '.join(privileges)} ON TABLE {table} TO app_user"
        )
    connection.exec_driver_sql(
        "GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO app_user"
    )


def transfer_migration_ownership(connection) -> None:
    """Make migration_user the owner of every application table.

    Table owners bypass RLS by default (we do not FORCE it), so
    `alembic upgrade head` running as migration_user can always see and
    modify the full schema, while app_user — never the owner — is always
    filtered. Running as the superuser (fresh bootstrap) works too;
    ALTER OWNER TO the current role is a no-op.
    """
    for table in _APP_USER_GRANTS:
        connection.exec_driver_sql(
            f"ALTER TABLE {table} OWNER TO migration_user"
        )


def _current_user_sql() -> str:
    # NULLIF so an empty-string GUC (current_setting missing_ok default)
    # never casts to a UUID and never matches rows — fail closed.
    return "NULLIF(current_setting('app.current_user_id', true), '')::uuid"


def _current_role_sql() -> str:
    return "current_setting('app.current_role', true)"


def enable_rls(connection) -> None:
    """Enable RLS and create the per-role policies on the four tables.

    USING (who can see rows) follows the task spec exactly:
      admin    → all rows
      citizen  → rows whose owner_id is them
      reviewer → rows on bundles assigned to them

    WITH CHECK (who can insert rows) is deliberately more permissive than
    USING for writes the API legitimately performs:
      - any role may INSERT a bundle/document/finding THEY own
        (a reviewer running POST /analyze with PERSIST_RESULTS creates a
        bundle they own but is not "assigned" — without this the insert
        would be rejected by a strict mirror of the USING clause);
      - only admins and the ASSIGNED reviewer may INSERT review_decisions,
        so a citizen can never record a decision even at the DB layer
        (defence in depth behind the API's require_role check).

    Every policy is written so that an UNSET GUC hides all rows and
    rejects all writes (fail closed): current_setting(..., true) returns
    NULL, NULL comparisons propagate, and nothing matches.
    """
    uid = _current_user_sql()
    role = _current_role_sql()

    for table in RLS_TABLES:
        connection.exec_driver_sql(
            f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"
        )
        # Drop existing policies so the setup is re-runnable (idempotent).
        connection.exec_driver_sql(
            f"DROP POLICY IF EXISTS {table}_access ON {table}"
        )

    # --- bundles: the root of the ownership graph -------------------------
    connection.exec_driver_sql(
        f"""
        CREATE POLICY bundles_access ON bundles FOR ALL TO app_user
        USING (
            {role} = 'admin'
            OR ({role} = 'citizen' AND owner_id = {uid})
            OR ({role} = 'reviewer' AND assigned_reviewer_id = {uid})
        )
        WITH CHECK (
            {role} = 'admin'
            OR owner_id = {uid}
        )
        """
    )

    # --- documents / findings_pg: filtered via their parent bundle ---------
    for table, fk in (("documents", "bundle_id"), ("findings_pg", "bundle_id")):
        connection.exec_driver_sql(
            f"""
            CREATE POLICY {table}_access ON {table} FOR ALL TO app_user
            USING (
                EXISTS (
                    SELECT 1 FROM bundles b
                    WHERE b.id = {table}.{fk}
                      AND (
                          {role} = 'admin'
                          OR ({role} = 'citizen' AND b.owner_id = {uid})
                          OR ({role} = 'reviewer' AND b.assigned_reviewer_id = {uid})
                      )
                )
            )
            WITH CHECK (
                EXISTS (
                    SELECT 1 FROM bundles b
                    WHERE b.id = {table}.{fk}
                      AND (
                          {role} = 'admin'
                          OR b.owner_id = {uid}
                          OR b.assigned_reviewer_id = {uid}
                      )
                )
            )
            """
        )

    # --- review_decisions: read via finding -> bundle; write is stricter --
    # USING: citizens see decisions on their own bundles (transparency);
    #        reviewers see decisions on bundles assigned to them; admin all.
    # WITH CHECK: only admin or the assigned reviewer may record a decision.
    #        A citizen INSERT is rejected here even though the API's
    #        require_role("reviewer", "admin") already blocks it — the
    #        database does not rely on the application alone.
    decision_join = """
        FROM findings_pg f JOIN bundles b ON b.id = f.bundle_id
        WHERE f.id = review_decisions.finding_id
    """
    connection.exec_driver_sql(
        f"""
        CREATE POLICY review_decisions_access ON review_decisions
        FOR ALL TO app_user
        USING (
            EXISTS (
                SELECT 1 {decision_join}
                  AND (
                      {role} = 'admin'
                      OR ({role} = 'citizen' AND b.owner_id = {uid})
                      OR ({role} = 'reviewer' AND b.assigned_reviewer_id = {uid})
                  )
            )
        )
        WITH CHECK (
            EXISTS (
                SELECT 1 {decision_join}
                  AND (
                      {role} = 'admin'
                      OR ({role} = 'reviewer' AND b.assigned_reviewer_id = {uid})
                  )
            )
        )
        """
    )


def setup_full_rls(connection, app_password: str,
                   migration_password: str) -> None:
    """One-call helper for migration 0006 and the RLS test suite:
    roles → passwords → schema grants → table grants → ownership → RLS."""
    setup_roles(connection, app_password, migration_password)
    grant_app_privileges(connection)
    transfer_migration_ownership(connection)
    enable_rls(connection)


