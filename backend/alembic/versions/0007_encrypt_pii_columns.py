"""encrypt_pii_columns

Revision ID: 0007
Revises: 0006
Create Date: 2025-01-07 00:00:00.000000

Widens the PII columns that now use app.security.crypto.EncryptedType
from VARCHAR(255) to TEXT so key-id-prefixed ciphertext cannot be
truncated. No data is rewritten here — existing plaintext/legacy rows are
re-encrypted by scripts/rotate_data_keys.py, which must be run after this
migration on any database that already holds PII.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users_pg") as batch_op:
        batch_op.alter_column(
            "totp_secret",
            type_=sa.Text(),
            existing_type=sa.String(255),
            existing_nullable=True,
        )
    with op.batch_alter_table("review_decisions") as batch_op:
        batch_op.alter_column(
            "reviewer_email",
            type_=sa.Text(),
            existing_type=sa.String(255),
            existing_nullable=False,
        )
    # findings_pg.reason is already TEXT — nothing to widen.


def downgrade() -> None:
    with op.batch_alter_table("review_decisions") as batch_op:
        batch_op.alter_column(
            "reviewer_email",
            type_=sa.String(255),
            existing_type=sa.Text(),
            existing_nullable=False,
        )
    with op.batch_alter_table("users_pg") as batch_op:
        batch_op.alter_column(
            "totp_secret",
            type_=sa.String(255),
            existing_type=sa.Text(),
            existing_nullable=True,
        )