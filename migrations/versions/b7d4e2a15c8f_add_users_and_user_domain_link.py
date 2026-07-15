"""add users table and user_id link on domain_verifications

Revision ID: b7d4e2a15c8f
Revises: a1c3f7b920de
Create Date: 2026-07-15 17:30:00.000000

Hosted-tier auth (config.REQUIRE_AUTH). The users table is inert for local/
self-hosted deployments — nothing writes to it unless REQUIRE_AUTH is on.
domain_verifications.user_id is nullable so the existing account-less claim-key
flow (REQUIRE_DOMAIN_VERIFICATION) is unaffected.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


revision: str = 'b7d4e2a15c8f'
down_revision: Union[str, None] = 'a1c3f7b920de'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'users',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('email_verified', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_users_email', 'users', ['email'], unique=True)

    op.add_column(
        'domain_verifications',
        sa.Column('user_id', UUID(as_uuid=True), nullable=True),
    )
    op.create_index('ix_domain_verifications_user_id', 'domain_verifications', ['user_id'])
    op.create_foreign_key(
        'fk_domain_verifications_user_id', 'domain_verifications', 'users',
        ['user_id'], ['id'],
    )


def downgrade() -> None:
    op.drop_constraint('fk_domain_verifications_user_id', 'domain_verifications', type_='foreignkey')
    op.drop_index('ix_domain_verifications_user_id', table_name='domain_verifications')
    op.drop_column('domain_verifications', 'user_id')
    op.drop_index('ix_users_email', table_name='users')
    op.drop_table('users')
