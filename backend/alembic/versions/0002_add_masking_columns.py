"""add_masking_columns

Revision ID: 0002
Revises: 0001
Create Date: 2025-01-02 00:00:00.000000

Adds data-minimization and file-storage columns to the documents table.
No PII is added — these columns store masked last-4 values, HMAC digests,
and file content-hashes only.

Security: masked_value stores only the last 4 characters of an identity field.
id_hash stores an HMAC-SHA256 digest used for cross-document matching.
Raw identity numbers are never stored in this table.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "documents",
        sa.Column("masked_value", sa.String(20), nullable=True),
    )
    op.add_column(
        "documents",
        sa.Column("id_hash", sa.String(64), nullable=True),
    )
    op.add_column(
        "documents",
        sa.Column("file_hash", sa.String(64), nullable=True),
    )
    op.add_column(
        "documents",
        sa.Column("storage_key", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("documents", "storage_key")
    op.drop_column("documents", "file_hash")
    op.drop_column("documents", "id_hash")
    op.drop_column("documents", "masked_value")
