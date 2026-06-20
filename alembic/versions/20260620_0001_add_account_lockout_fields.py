"""add account lockout fields

Revision ID: 20260620_0001_lockout
Revises: a8adbe723df6
Create Date: 2026-06-20 00:00:00.000000+00:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "20260620_0001_lockout"
down_revision: Union[str, Sequence[str], None] = "a8adbe723df6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column("users", sa.Column("login_locked_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("last_failed_login_at", sa.DateTime(timezone=True), nullable=True))
    op.alter_column("users", "failed_login_attempts", server_default=None)


def downgrade() -> None:
    op.drop_column("users", "last_failed_login_at")
    op.drop_column("users", "login_locked_until")
    op.drop_column("users", "failed_login_attempts")
