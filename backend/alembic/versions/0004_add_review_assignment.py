"""add_review_assignment

Revision ID: 0004
Revises: 0003
Create Date: 2025-01-04 00:00:00.000000

Adds reviewer-assignment support for the review decision workflow:
- bundles.assigned_reviewer_id: which reviewer may decide on the bundle
- review_decisions.reviewer_id: opaque UUID attribution for each decision

No PII is added — both columns are foreign keys to users_pg.id.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # batch_alter_table keeps the migration working on SQLite (which lacks
    # ALTER TABLE ... ADD CONSTRAINT) while emitting plain ALTERs on Postgres.
    with op.batch_alter_table("bundles") as batch_op:
        batch_op.add_column(
            sa.Column("assigned_reviewer_id", sa.Uuid(), nullable=True)
        )
        batch_op.create_foreign_key(
            "fk_bundles_assigned_reviewer",
            "users_pg",
            ["assigned_reviewer_id"],
            ["id"],
            ondelete="SET NULL",
        )

    with op.batch_alter_table("review_decisions") as batch_op:
        batch_op.add_column(
            sa.Column("reviewer_id", sa.Uuid(), nullable=True)
        )
        batch_op.create_foreign_key(
            "fk_review_decisions_reviewer",
            "users_pg",
            ["reviewer_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    with op.batch_alter_table("review_decisions") as batch_op:
        batch_op.drop_constraint(
            "fk_review_decisions_reviewer", type_="foreignkey"
        )
        batch_op.drop_column("reviewer_id")

    with op.batch_alter_table("bundles") as batch_op:
        batch_op.drop_constraint(
            "fk_bundles_assigned_reviewer", type_="foreignkey"
        )
        batch_op.drop_column("assigned_reviewer_id")