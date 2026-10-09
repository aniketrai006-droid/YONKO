"""initial_schema

Revision ID: 0001
Revises: None (first migration)
Create Date: 2025-01-01 00:00:00.000000

Hand-written migration — does NOT require a live database to generate.
Covers all six tables: users_pg, bundles, documents, findings_pg,
review_decisions, audit_log_pg.

Security: audit_log_pg has no PII columns. actor_id is an opaque identifier.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# Alembic revision identifiers
revision: str = "0001"
down_revision: str | None = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create all six tables for the YONKO database schema."""

    # ------------------------------------------------------------------
    # users_pg — reviewer and operator accounts
    # ------------------------------------------------------------------
    op.create_table(
        "users_pg",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column(
            "role",
            sa.String(50),
            nullable=False,
            server_default="reviewer",
        ),
        sa.Column("is_active", sa.Boolean(), nullable=True, server_default="true"),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=True,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
    )

    # ------------------------------------------------------------------
    # bundles — submission groups
    # ------------------------------------------------------------------
    op.create_table(
        "bundles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_email", sa.String(255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=True,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("bundle_ref", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ["owner_email"],
            ["users_pg.email"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # ------------------------------------------------------------------
    # documents — file metadata only (no bytes stored)
    # ------------------------------------------------------------------
    op.create_table(
        "documents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("bundle_id", sa.Uuid(), nullable=False),
        sa.Column("filename", sa.Text(), nullable=False),
        sa.Column("document_type", sa.String(100), nullable=True),
        sa.Column("page_count", sa.Integer(), nullable=True, server_default="1"),
        sa.ForeignKeyConstraint(
            ["bundle_id"],
            ["bundles.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # ------------------------------------------------------------------
    # findings_pg — contradiction findings from /analyze
    # ------------------------------------------------------------------
    op.create_table(
        "findings_pg",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("bundle_id", sa.Uuid(), nullable=False),
        sa.Column("field", sa.String(255), nullable=False),
        sa.Column("decision", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("similarity", sa.Float(), nullable=True),
        sa.Column("recommended_action", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["bundle_id"],
            ["bundles.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # ------------------------------------------------------------------
    # review_decisions — human reviewer decisions on findings
    # ------------------------------------------------------------------
    op.create_table(
        "review_decisions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("reviewer_email", sa.String(255), nullable=False),
        sa.Column("decision", sa.String(50), nullable=False),
        sa.Column(
            "decided_at",
            sa.DateTime(),
            nullable=True,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings_pg.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # ------------------------------------------------------------------
    # audit_log_pg — security audit trail
    #
    # Security: no PII columns. actor_id is an opaque identifier only.
    # No 'email', 'name', 'dob', 'aadhaar', or 'pan' columns here.
    # ------------------------------------------------------------------
    op.create_table(
        "audit_log_pg",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "ts",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("actor_id", sa.String(255), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource_type", sa.String(100), nullable=True),
        sa.Column("resource_id", sa.String(255), nullable=True),
        sa.Column("outcome", sa.String(50), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    """Drop all six tables in reverse dependency order."""
    op.drop_table("audit_log_pg")
    op.drop_table("review_decisions")
    op.drop_table("findings_pg")
    op.drop_table("documents")
    op.drop_table("bundles")
    op.drop_table("users_pg")
