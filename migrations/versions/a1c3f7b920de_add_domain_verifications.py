"""add domain_verifications table

Revision ID: a1c3f7b920de
Revises: 5c200e4261e5
Create Date: 2026-07-14 09:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


revision: str = 'a1c3f7b920de'
down_revision: Union[str, None] = '5c200e4261e5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'domain_verifications',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('domain', sa.String(length=255), nullable=False),
        sa.Column('method', sa.String(length=16), nullable=False),
        sa.Column('token', sa.String(length=96), nullable=False),
        sa.Column('key_hash', sa.String(length=64), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=False, server_default='pending'),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('verified_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_domain_verifications_domain', 'domain_verifications', ['domain'])


def downgrade() -> None:
    op.drop_index('ix_domain_verifications_domain', table_name='domain_verifications')
    op.drop_table('domain_verifications')
