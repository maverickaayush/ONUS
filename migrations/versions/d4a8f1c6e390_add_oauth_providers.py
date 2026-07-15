"""add auth_providers (OAuth) and make users.password_hash nullable

Revision ID: d4a8f1c6e390
Revises: c9f1a3e8b204
Create Date: 2026-07-16 04:20:00.000000

Hosted OAuth (config.REQUIRE_AUTH). Additive + one column relaxation:
  * auth_providers: external identities linked to a user (google/github).
  * users.password_hash -> nullable, so OAuth-only users need no password.
Existing password users are unaffected (their hash stays set).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB


revision: str = 'd4a8f1c6e390'
down_revision: Union[str, None] = 'c9f1a3e8b204'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column('users', 'password_hash', existing_type=sa.String(length=255), nullable=True)

    op.create_table(
        'auth_providers',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('provider', sa.String(length=16), nullable=False),
        sa.Column('provider_user_id', sa.String(length=255), nullable=False),
        sa.Column('provider_metadata', JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.UniqueConstraint('provider', 'provider_user_id', name='uq_provider_identity'),
    )
    op.create_index('ix_auth_providers_user_id', 'auth_providers', ['user_id'])


def downgrade() -> None:
    op.drop_index('ix_auth_providers_user_id', table_name='auth_providers')
    op.drop_table('auth_providers')
    # Note: reverting nullable requires no NULL password_hash rows to exist.
    op.alter_column('users', 'password_hash', existing_type=sa.String(length=255), nullable=False)
