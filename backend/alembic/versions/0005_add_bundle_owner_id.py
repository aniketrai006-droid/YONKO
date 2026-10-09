"""add_bundle_owner_id

Revision ID: 0005
Revises: 0004
Create Date: 2025-01-05 00:00:00.000000

Adds bundles.owner_id (UUID FK to users_pg.id) — the authoritative owner
pointer used by the PostgreSQL Row-Level Security citizen policy. Existing
rows are backfilled from owner_email via users_pg; rows whose owner_email
has no matching users_pg row keep NULL (visible to admins only), which is
the fail-closed direction for a security column.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("bundles") as batch_op:
        batch_op.add_column(
            sa.Column("owner_id", sa.Uuid(), nullable=True)
        )
        batch_op.create_foreign_key(
            "fk_bundles_owner_id",
            "users_pg",
            ["owner_id"],
            ["id"],
            ondelete="SET NULL",
        )

    # Backfill from owner_email. Parameterised UPDATE — steering rule 3.
    op.execute(
        sa.text(
            "UPDATE bundles SET owner_id = ("
            "SELECT u.id FROM users_pg u WHERE u.email = bundles.owner_email"
            ") WHERE owner_id IS NULL"
        )
    )


def downgrade() -> None:
    with op.batch_alter_table("bundles") as batch_op:
        batch_op.drop_constraint(
            "fk_bundles_owner_id", type_="foreignkey"
        )
        batch_op.drop_column("owner_id")