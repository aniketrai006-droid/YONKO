"""add_auth_columns

Revision ID: 0003
Revises: 0002
Create Date: 2025-01-03 00:00:00.000000

Adds the JWT auth system columns and the refresh_tokens table.
No PII is added — totp_secret stores an AES-GCM-encrypted TOTP shared
secret; refresh_tokens stores only SHA-256 hashes of issued tokens.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users_pg",
        sa.Column("totp_secret", sa.String(255), nullable=True),
    )
    op.add_column(
        "users_pg",
        sa.Column(
            "failed_attempts",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "users_pg",
        sa.Column("locked_until", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("family_id", sa.Uuid(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column(
            "used", sa.Boolean(), nullable=False, server_default="false"
        ),
        sa.Column(
            "revoked", sa.Boolean(), nullable=False, server_default="false"
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=True,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users_pg.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["family_id"], ["refresh_tokens.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )


def downgrade() -> None:
    op.drop_table("refresh_tokens")
    op.drop_column("users_pg", "locked_until")
    op.drop_column("users_pg", "failed_attempts")
    op.drop_column("users_pg", "totp_secret")