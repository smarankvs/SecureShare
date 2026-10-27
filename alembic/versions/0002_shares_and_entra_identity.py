"""shares_and_entra_identity

Adds Microsoft Entra ID identity mapping to `users` and the `shares` table used by
the recipient-bound, quota-limited sharing policy engine.

Revision ID: 0002_shares_and_entra
Revises: 0001_initial_schema
Create Date: 2026-10-27 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0002_shares_and_entra"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # 1. users: Entra ID identity mapping
    # ------------------------------------------------------------------
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("entra_oid", sa.String(length=64), nullable=True))
        batch_op.add_column(
            sa.Column(
                "auth_source",
                sa.String(length=20),
                nullable=False,
                server_default=sa.text("'local'"),
            )
        )
        # Local password auth is replaced by Entra ID for federated accounts.
        batch_op.alter_column(
            "password_hash",
            existing_type=sa.String(length=255),
            nullable=True,
        )
        batch_op.create_index("ix_users_entra_oid", ["entra_oid"], unique=True)

    # ------------------------------------------------------------------
    # 2. shares: recipient-bound access grants
    # ------------------------------------------------------------------
    op.create_table(
        "shares",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("file_id", sa.String(length=36), nullable=False),
        sa.Column("created_by", sa.String(length=36), nullable=False),
        sa.Column("recipient_email", sa.String(length=255), nullable=False),
        sa.Column("recipient_user_id", sa.String(length=36), nullable=True),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("token_prefix", sa.String(length=12), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default=sa.text("'ACTIVE'")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("max_downloads", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("download_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_downloaded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(["file_id"], ["files.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["recipient_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["revoked_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_shares_id"), "shares", ["id"], unique=False)
    op.create_index(op.f("ix_shares_file_id"), "shares", ["file_id"], unique=False)
    op.create_index(op.f("ix_shares_created_by"), "shares", ["created_by"], unique=False)
    op.create_index(op.f("ix_shares_recipient_email"), "shares", ["recipient_email"], unique=False)
    op.create_index(op.f("ix_shares_recipient_user_id"), "shares", ["recipient_user_id"], unique=False)
    op.create_index(op.f("ix_shares_status"), "shares", ["status"], unique=False)
    op.create_index(op.f("ix_shares_token_hash"), "shares", ["token_hash"], unique=True)


def downgrade() -> None:
    op.drop_index(op.f("ix_shares_token_hash"), table_name="shares")
    op.drop_index(op.f("ix_shares_status"), table_name="shares")
    op.drop_index(op.f("ix_shares_recipient_user_id"), table_name="shares")
    op.drop_index(op.f("ix_shares_recipient_email"), table_name="shares")
    op.drop_index(op.f("ix_shares_created_by"), table_name="shares")
    op.drop_index(op.f("ix_shares_file_id"), table_name="shares")
    op.drop_index(op.f("ix_shares_id"), table_name="shares")
    op.drop_table("shares")

    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_index("ix_users_entra_oid")
        batch_op.alter_column(
            "password_hash",
            existing_type=sa.String(length=255),
            nullable=False,
        )
        batch_op.drop_column("auth_source")
        batch_op.drop_column("entra_oid")
