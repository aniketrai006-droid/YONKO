"""
Alembic migration environment for YONKO.

Imports Base from app.models so that autogenerate can reflect the ORM
metadata. The DATABASE_URL is read from app.config (which reads from the
environment / .env file) so that migration commands always use the same
URL as the running application — no separate config needed.

Security: this file contains no hardcoded credentials. All connection
details come from the environment via app.config.settings.
"""

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config, pool

from alembic import context

# Ensure the backend/ directory is on sys.path so `from app.xxx` imports work
# when alembic is run from the backend/ directory (cd backend && alembic ...).
_backend_dir = Path(__file__).resolve().parents[1]
if str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))

# Import app models so that Base.metadata is populated before any migration runs.
from app.models import Base  # noqa: E402
from app.config import settings  # noqa: E402

# Alembic Config object — access to values in the .ini file.
config = context.config

# Override sqlalchemy.url so there is one source of truth.
# MIGRATION_DATABASE_URL (migration_user credentials) takes precedence over
# DATABASE_URL (app_user credentials) so that DDL runs with the elevated
# migration role while the API connects with least privilege.
# This means `alembic upgrade head` uses the migration role when configured.
_migration_url = os.environ.get("MIGRATION_DATABASE_URL") or settings.DATABASE_URL
config.set_main_option("sqlalchemy.url", _migration_url)

# Set up Python logging from the alembic.ini [loggers] section.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# target_metadata points at our ORM Base so autogenerate works.
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode (no live DB connection required).

    Emits SQL to stdout instead of executing against the database.
    Useful for generating SQL scripts for DBA review.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode (connects to the live database).

    Uses a synchronous engine — no async here, consistent with the
    rest of the application's sync SQLAlchemy usage.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
