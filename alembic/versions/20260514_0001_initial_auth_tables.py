"""create initial auth tables

Revision ID: 0001_initial_auth_tables
Revises:
Create Date: 2026-05-14 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial_auth_tables"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    auth_type = postgresql.ENUM("EMAIL", "GOOGLE", name="authtype")
    auth_type_column = postgresql.ENUM(
        "EMAIL",
        "GOOGLE",
        name="authtype",
        create_type=False,
    )
    auth_type.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "users",
        sa.Column("_id", sa.String(), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password", sa.String(length=255), nullable=True),
        sa.Column("full_name", sa.String(length=255), nullable=True),
        sa.Column("google_sub", sa.String(length=255), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("is_superuser", sa.Boolean(), nullable=False),
        sa.Column("is_verified", sa.Boolean(), nullable=False),
        sa.Column("auth_type", auth_type_column, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("_id"),
        sa.UniqueConstraint("email"),
    )

    op.create_table(
        "email_verification_tokens",
        sa.Column("_id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("token", sa.String(), nullable=False),
        sa.Column("is_used", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users._id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("_id"),
    )
    op.create_index("ix_email_verification_tokens_token", "email_verification_tokens", ["token"], unique=True)
    op.create_index("ix_email_verification_tokens_user_id", "email_verification_tokens", ["user_id"], unique=True)

    op.create_table(
        "password_reset_tokens",
        sa.Column("_id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("token", sa.String(), nullable=False),
        sa.Column("is_used", sa.Boolean(), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cooldown_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cooldown_reset_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users._id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("_id"),
    )
    op.create_index("ix_password_reset_tokens_token", "password_reset_tokens", ["token"], unique=True)
    op.create_index("ix_password_reset_tokens_user_id", "password_reset_tokens", ["user_id"], unique=True)

    op.create_table(
        "user_authenticator_apps",
        sa.Column("_id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("secret", sa.String(length=64), nullable=False),
        sa.Column("issuer", sa.String(length=255), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False),
        sa.Column("last_used_counter", sa.Integer(), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users._id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("_id"),
    )
    op.create_index("ix_user_authenticator_apps_is_enabled", "user_authenticator_apps", ["is_enabled"])
    op.create_index("ix_user_authenticator_apps_user_id", "user_authenticator_apps", ["user_id"], unique=True)

    op.create_table(
        "user_profiles",
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("image_path", sa.String(length=512), nullable=True),
        sa.Column("image_url", sa.String(length=2048), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users._id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id"),
    )

    op.create_table(
        "user_sessions",
        sa.Column("_id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("device_id", sa.String(length=255), nullable=True),
        sa.Column("device_key_hash", sa.String(length=128), nullable=False),
        sa.Column("device_name", sa.String(length=255), nullable=True),
        sa.Column("device_type", sa.String(length=50), nullable=True),
        sa.Column("os_name", sa.String(length=100), nullable=True),
        sa.Column("browser_name", sa.String(length=100), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(length=100), nullable=True),
        sa.Column("last_ip_address", sa.String(length=100), nullable=True),
        sa.Column("refresh_token_hash", sa.String(length=128), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("logged_out_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users._id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("_id"),
        sa.UniqueConstraint("user_id", "device_key_hash", name="uq_user_sessions_user_id_device_key_hash"),
    )
    op.create_index("ix_user_sessions_device_key_hash", "user_sessions", ["device_key_hash"])
    op.create_index("ix_user_sessions_expires_at", "user_sessions", ["expires_at"])
    op.create_index("ix_user_sessions_is_active", "user_sessions", ["is_active"])
    op.create_index("ix_user_sessions_last_seen_at", "user_sessions", ["last_seen_at"])
    op.create_index("ix_user_sessions_refresh_token_hash", "user_sessions", ["refresh_token_hash"], unique=True)
    op.create_index("ix_user_sessions_user_active_last_seen", "user_sessions", ["user_id", "is_active", "last_seen_at"])
    op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_user_sessions_user_id", table_name="user_sessions")
    op.drop_index("ix_user_sessions_user_active_last_seen", table_name="user_sessions")
    op.drop_index("ix_user_sessions_refresh_token_hash", table_name="user_sessions")
    op.drop_index("ix_user_sessions_last_seen_at", table_name="user_sessions")
    op.drop_index("ix_user_sessions_is_active", table_name="user_sessions")
    op.drop_index("ix_user_sessions_expires_at", table_name="user_sessions")
    op.drop_index("ix_user_sessions_device_key_hash", table_name="user_sessions")
    op.drop_table("user_sessions")
    op.drop_table("user_profiles")
    op.drop_index("ix_user_authenticator_apps_user_id", table_name="user_authenticator_apps")
    op.drop_index("ix_user_authenticator_apps_is_enabled", table_name="user_authenticator_apps")
    op.drop_table("user_authenticator_apps")
    op.drop_index("ix_password_reset_tokens_user_id", table_name="password_reset_tokens")
    op.drop_index("ix_password_reset_tokens_token", table_name="password_reset_tokens")
    op.drop_table("password_reset_tokens")
    op.drop_index("ix_email_verification_tokens_user_id", table_name="email_verification_tokens")
    op.drop_index("ix_email_verification_tokens_token", table_name="email_verification_tokens")
    op.drop_table("email_verification_tokens")
    op.drop_table("users")
    auth_type = postgresql.ENUM("EMAIL", "GOOGLE", name="authtype")
    auth_type.drop(op.get_bind(), checkfirst=True)
