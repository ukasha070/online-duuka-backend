"""cascade auth token foreign keys

Revision ID: 0002_cascade_auth_token_fks
Revises: 0001_initial_auth_tables
Create Date: 2026-05-14 00:40:00.000000
"""

from typing import Sequence, Union

from alembic import op

revision: str = "0002_cascade_auth_token_fks"
down_revision: Union[str, Sequence[str], None] = "0001_initial_auth_tables"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint(
        "email_verification_tokens_user_id_fkey",
        "email_verification_tokens",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "email_verification_tokens_user_id_fkey",
        "email_verification_tokens",
        "users",
        ["user_id"],
        ["_id"],
        ondelete="CASCADE",
    )

    op.drop_constraint(
        "password_reset_tokens_user_id_fkey",
        "password_reset_tokens",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "password_reset_tokens_user_id_fkey",
        "password_reset_tokens",
        "users",
        ["user_id"],
        ["_id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    op.drop_constraint(
        "password_reset_tokens_user_id_fkey",
        "password_reset_tokens",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "password_reset_tokens_user_id_fkey",
        "password_reset_tokens",
        "users",
        ["user_id"],
        ["_id"],
    )

    op.drop_constraint(
        "email_verification_tokens_user_id_fkey",
        "email_verification_tokens",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "email_verification_tokens_user_id_fkey",
        "email_verification_tokens",
        "users",
        ["user_id"],
        ["_id"],
    )
