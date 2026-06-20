"""add two-factor recovery codes

Revision ID: 0003_two_factor_recovery_codes
Revises: 0002_cascade_auth_token_fks
Create Date: 2026-05-14 23:30:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0003_two_factor_recovery_codes"
down_revision: Union[str, Sequence[str], None] = "0002_cascade_auth_token_fks"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "user_authenticator_apps",
        "secret",
        existing_type=sa.String(length=64),
        type_=sa.String(length=512),
        existing_nullable=False,
    )

    op.create_table(
        "user_two_factor_recovery_codes",
        sa.Column("_id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("code_hash", sa.String(length=128), nullable=False),
        sa.Column("is_used", sa.Boolean(), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users._id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("_id"),
    )
    op.create_index("ix_user_two_factor_recovery_codes_code_hash", "user_two_factor_recovery_codes", ["code_hash"], unique=True)
    op.create_index("ix_user_two_factor_recovery_codes_is_used", "user_two_factor_recovery_codes", ["is_used"])
    op.create_index("ix_user_two_factor_recovery_codes_user_id", "user_two_factor_recovery_codes", ["user_id"])
    op.create_index("ix_user_two_factor_recovery_codes_user_unused", "user_two_factor_recovery_codes", ["user_id", "is_used"])


def downgrade() -> None:
    op.drop_index("ix_user_two_factor_recovery_codes_user_unused", table_name="user_two_factor_recovery_codes")
    op.drop_index("ix_user_two_factor_recovery_codes_user_id", table_name="user_two_factor_recovery_codes")
    op.drop_index("ix_user_two_factor_recovery_codes_is_used", table_name="user_two_factor_recovery_codes")
    op.drop_index("ix_user_two_factor_recovery_codes_code_hash", table_name="user_two_factor_recovery_codes")
    op.drop_table("user_two_factor_recovery_codes")

    op.alter_column(
        "user_authenticator_apps",
        "secret",
        existing_type=sa.String(length=512),
        type_=sa.String(length=64),
        existing_nullable=False,
    )
