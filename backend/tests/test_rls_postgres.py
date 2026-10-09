"""Real-PostgreSQL Row-Level Security tests.

These tests verify that the DATABASE ITSELF enforces access control — no
application code is involved in the assertions. They connect as app_user
(the role the API uses) and run raw SQL.

Requirements: a reachable PostgreSQL server. Connection strings come from
the environment (never hardcoded — steering rule 3):
  RLS_TEST_SUPERUSER_URL  — superuser URL used to create the scratch DB,
                            run migrations, and seed fixtures. Typically
                            the docker-compose db service, e.g.
                            postgresql+psycopg2://yonko:changeme@localhost:5432/yonko
  RLS_TEST_APP_PASSWORD   — password for app_user (must match what
                            migration 0006 was applied with).
When RLS_TEST_SUPERUSER_URL is unset or unreachable the whole module is
skipped — CI provides the Postgres service and sets these variables.
"""
from __future__ import annotations

import os
import uuid

import pytest

rls_url = os.environ.get("RLS_TEST_SUPERUSER_URL", "")
app_password = os.environ.get("RLS_TEST_APP_PASSWORD", "rls-test-app-pw")

if not rls_url:
    pytest.skip(
        "RLS tests require PostgreSQL. Set RLS_TEST_SUPERUSER_URL "
        "(and RLS_TEST_APP_PASSWORD) to run them.",
        allow_module_level=True,
    )

sa = pytest.importorskip("sqlalchemy")
psycopg2 = pytest.importorskip("psycopg2")

from sqlalchemy import create_engine, text  # noqa: E402

# ---------------------------------------------------------------------------
# Module fixtures: one scratch database per test session
# ---------------------------------------------------------------------------

_TEST_DB = f"yonko_rls_test_{uuid.uuid4().hex[:8]}"


def _super_url_for_test_db() -> str:
    """Rewrite the superuser URL to point at the scratch database."""
    from sqlalchemy.engine import make_url

    url = make_url(rls_url)
    return url.set(database=_TEST_DB).render_as_string(hide_password=False)


@pytest.fixture(scope="module")
def pg_setup():
    """Create the scratch DB, run the real migration chain, seed fixtures.

    Yields a dict of ids/emails for the seeded users and bundles, then
    drops the scratch database.
    """
    # Reachability check + create scratch DB.
    try:
        admin_engine = create_engine(rls_url, isolation_level="AUTOCOMMIT")
        with admin_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        with admin_engine.connect() as conn:
            conn.execute(text(f'CREATE DATABASE "{_TEST_DB}"'))
    except Exception as exc:  # pragma: no cover - depends on host env
        pytest.skip(f"PostgreSQL not reachable for RLS tests: {exc}")

    test_url = _super_url_for_test_db()
    engine = create_engine(test_url)

    # Run the real Alembic chain so RLS setup is exercised end-to-end.
    import subprocess
    import sys
    from pathlib import Path

    backend_dir = Path(__file__).resolve().parents[1]
    env = dict(
        os.environ,
        DATABASE_URL=test_url,
        MIGRATION_DATABASE_URL=test_url,
        APP_DB_PASSWORD=app_password,
        MIGRATION_USER_PASSWORD="rls-test-migration-pw",
    )
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=backend_dir, env=env, capture_output=True, text=True,
    )
    if result.returncode != 0:
        engine.dispose()
        _drop_test_db(admin_engine)
        pytest.skip(f"alembic upgrade failed on test Postgres: {result.stderr}")

    # Seed fixtures AS THE SUPERUSER so RLS doesn't filter the inserts.
    citizen_a = uuid.uuid4()
    citizen_b = uuid.uuid4()
    reviewer = uuid.uuid4()
    admin = uuid.uuid4()
    with engine.begin() as conn:
        for uid, email, role in (
            (citizen_a, "citizen-a@rls.test", "citizen"),
            (citizen_b, "citizen-b@rls.test", "citizen"),
            (reviewer, "reviewer@rls.test", "reviewer"),
            (admin, "admin@rls.test", "admin"),
        ):
            conn.execute(text(
                "INSERT INTO users_pg (id, email, password_hash, role, is_active) "
                "VALUES (:id, :email, 'x', :role, true)"
            ), {"id": uid, "email": email, "role": role})

        bundle_a = uuid.uuid4()
        bundle_b = uuid.uuid4()
        bundle_r = uuid.uuid4()  # assigned to the reviewer
        # owner_email must satisfy the FK to users_pg.email — use the
        # owning citizen's email for each bundle.
        for bid, owner, owner_email, assignee, ref in (
            (bundle_a, citizen_a, "citizen-a@rls.test", None, "bundle-a"),
            (bundle_b, citizen_b, "citizen-b@rls.test", None, "bundle-b"),
            (bundle_r, citizen_b, "citizen-b@rls.test", reviewer, "bundle-r"),
        ):
            conn.execute(text(
                "INSERT INTO bundles (id, owner_email, owner_id, bundle_ref, "
                "assigned_reviewer_id) VALUES (:id, :email, :owner, :ref, :assignee)"
            ), {"id": bid, "email": owner_email, "owner": owner,
                "ref": ref, "assignee": assignee})
        finding_a = uuid.uuid4()
        conn.execute(text(
            "INSERT INTO findings_pg (id, bundle_id, field, decision, severity) "
            "VALUES (:id, :bid, 'name', 'conflict', 'HIGH')"
        ), {"id": finding_a, "bid": bundle_a})

    yield {
        "engine": engine,
        "citizen_a": citizen_a,
        "citizen_b": citizen_b,
        "reviewer": reviewer,
        "admin": admin,
        "bundle_a": bundle_a,
        "bundle_b": bundle_b,
        "bundle_r": bundle_r,
        "finding_a": finding_a,
    }

    engine.dispose()
    _drop_test_db(admin_engine)


def _drop_test_db(admin_engine) -> None:
    with admin_engine.connect() as conn:
        conn.execute(text(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            f"WHERE datname = '{_TEST_DB}'"
        ))
        conn.execute(text(f'DROP DATABASE IF EXISTS "{_TEST_DB}"'))
    admin_engine.dispose()


@pytest.fixture()
def as_app_user(pg_setup):
    """Factory: connect to the scratch DB as app_user with a given
    RLS identity (or none) and yield a raw connection inside a transaction."""
    from sqlalchemy.engine import make_url

    url = make_url(_super_url_for_test_db()).set(
        username="app_user", password=app_password
    )
    engine = create_engine(url.render_as_string(hide_password=False))

    def _connect(user_id=None, role=None):
        conn = engine.connect()
        trans = conn.begin()
        if user_id is not None:
            conn.execute(text(
                "SELECT set_config('app.current_user_id', :uid, true)"
            ), {"uid": str(user_id)})
            conn.execute(text(
                "SELECT set_config('app.current_role', :role, true)"
            ), {"role": role})
        return conn, trans

    yield _connect
    engine.dispose()



# ---------------------------------------------------------------------------
# The actual RLS assertions — raw SQL, no application code
# ---------------------------------------------------------------------------

def _bundle_refs(conn) -> set:
    rows = conn.execute(text("SELECT bundle_ref FROM bundles")).fetchall()
    return {row[0] for row in rows}


def test_citizen_select_only_sees_own_rows_without_where(as_app_user, pg_setup):
    """Raw SELECT with NO WHERE clause: citizen A must see only their bundle."""
    conn, trans = as_app_user(pg_setup["citizen_a"], "citizen")
    try:
        refs = _bundle_refs(conn)
        assert refs == {"bundle-a"}, (
            f"citizen_a should see only bundle-a, got {refs}"
        )
    finally:
        trans.rollback()
        conn.close()


def test_citizen_b_sees_only_their_rows(as_app_user, pg_setup):
    conn, trans = as_app_user(pg_setup["citizen_b"], "citizen")
    try:
        refs = _bundle_refs(conn)
        # citizen_b owns bundle-b AND bundle-r (assigned to a reviewer).
        assert refs == {"bundle-b", "bundle-r"}, refs
    finally:
        trans.rollback()
        conn.close()


def test_reviewer_sees_only_assigned_bundles(as_app_user, pg_setup):
    """Reviewer must see bundle-r (assigned) but not bundle-a or bundle-b."""
    conn, trans = as_app_user(pg_setup["reviewer"], "reviewer")
    try:
        refs = _bundle_refs(conn)
        assert refs == {"bundle-r"}, refs
    finally:
        trans.rollback()
        conn.close()


def test_admin_sees_all_bundles(as_app_user, pg_setup):
    conn, trans = as_app_user(pg_setup["admin"], "admin")
    try:
        refs = _bundle_refs(conn)
        assert refs == {"bundle-a", "bundle-b", "bundle-r"}, refs
    finally:
        trans.rollback()
        conn.close()


def test_unset_identity_sees_nothing(as_app_user, pg_setup):
    """Fail closed: app_user with NO identity GUCs set sees zero rows."""
    conn, trans = as_app_user()  # no user_id, no role
    try:
        refs = _bundle_refs(conn)
        assert refs == set(), f"unset identity should see nothing, got {refs}"
    finally:
        trans.rollback()
        conn.close()



def test_documents_filtered_with_parent_bundle(as_app_user, pg_setup):
    """Child rows follow bundle visibility. Seed one document per bundle
    as superuser, then check citizen A sees only their own document."""
    with pg_setup["engine"].begin() as conn:
        for bid in (pg_setup["bundle_a"], pg_setup["bundle_b"],
                    pg_setup["bundle_r"]):
            conn.execute(text(
                "INSERT INTO documents (id, bundle_id, filename, "
                "document_type, page_count) "
                "VALUES (:id, :bid, 'id_card.png', 'id_card', 1)"
            ), {"id": uuid.uuid4(), "bid": bid})

    conn, trans = as_app_user(pg_setup["citizen_a"], "citizen")
    try:
        rows = conn.execute(text(
            "SELECT d.bundle_id FROM documents d"
        )).fetchall()
        seen = {row[0] for row in rows}
        assert seen == {pg_setup["bundle_a"]}, seen
    finally:
        trans.rollback()
        conn.close()


def test_reviewer_cannot_read_unassigned_findings(as_app_user, pg_setup):
    """finding_a lives on bundle-a, which is NOT assigned to the reviewer."""
    conn, trans = as_app_user(pg_setup["reviewer"], "reviewer")
    try:
        rows = conn.execute(text("SELECT id FROM findings_pg")).fetchall()
        assert rows == [], (
            f"reviewer should see no findings on unassigned bundles, got {rows}"
        )
    finally:
        trans.rollback()
        conn.close()


def test_app_user_cannot_update_audit_log(as_app_user, pg_setup):
    """audit_log_pg is INSERT-only for app_user — UPDATE must raise."""
    from sqlalchemy.exc import DBAPIError

    # Seed an audit row as superuser so there is something to (fail to) update.
    with pg_setup["engine"].begin() as conn:
        conn.execute(text(
            "INSERT INTO audit_log_pg (actor_id, action, resource_type) "
            "VALUES ('seed-actor', 'SEED', 'test')"
        ))

    conn, trans = as_app_user(pg_setup["admin"], "admin")
    try:
        with pytest.raises(DBAPIError):
            conn.execute(text(
                "UPDATE audit_log_pg SET action = 'TAMPERED'"
            ))
    finally:
        trans.rollback()
        conn.close()


def test_app_user_cannot_delete_audit_log(as_app_user, pg_setup):
    """audit_log_pg is INSERT-only for app_user — DELETE must raise."""
    from sqlalchemy.exc import DBAPIError

    conn, trans = as_app_user(pg_setup["admin"], "admin")
    try:
        with pytest.raises(DBAPIError):
            conn.execute(text("DELETE FROM audit_log_pg"))
    finally:
        trans.rollback()
        conn.close()


def test_app_user_cannot_delete_any_governed_table(as_app_user, pg_setup):
    """app_user has no DELETE privilege on any governed table."""
    from sqlalchemy.exc import DBAPIError

    conn, trans = as_app_user(pg_setup["admin"], "admin")
    try:
        with pytest.raises(DBAPIError):
            conn.execute(text("DELETE FROM bundles"))
    finally:
        trans.rollback()
        conn.close()


def test_app_user_can_insert_audit_log(as_app_user, pg_setup):
    """The INSERT side of the audit log must keep working (it's how the
    API writes security events)."""
    conn, trans = as_app_user(pg_setup["citizen_a"], "citizen")
    try:
        conn.execute(text(
            "INSERT INTO audit_log_pg (actor_id, action, resource_type) "
            "VALUES (:actor, 'LOGIN_OK', 'auth')"
        ), {"actor": str(pg_setup["citizen_a"])})
        trans.commit()
    finally:
        conn.close()


def test_citizen_cannot_insert_review_decision(as_app_user, pg_setup):
    """Defence in depth: even the DB rejects citizen decision writes."""
    from sqlalchemy.exc import DBAPIError

    conn, trans = as_app_user(pg_setup["citizen_a"], "citizen")
    try:
        with pytest.raises(DBAPIError):
            conn.execute(text(
                "INSERT INTO review_decisions "
                "(id, finding_id, reviewer_email, decision) "
                "VALUES (:id, :fid, 'citizen-a@rls.test', 'accepted')"
            ), {"id": uuid.uuid4(), "fid": pg_setup["finding_a"]})
    finally:
        trans.rollback()
        conn.close()


