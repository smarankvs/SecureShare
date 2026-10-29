"""add_username_to_users

Adds an optional unique username column to the `users` table for identifier-based authentication.

Revision ID: 0003_add_username
Revises: 0002_shares_and_entra
Create Date: 2026-10-29 10:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0003_add_username"
down_revision: Union[str, None] = "0002_shares_and_entra"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("username", sa.String(length=50), nullable=True))
        batch_op.create_index("ix_users_username", ["username"], unique=True)


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_index("ix_users_username")
        batch_op.drop_column("username")
