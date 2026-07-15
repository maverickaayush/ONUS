"""add scan_type and user_id to scans

Revision ID: c9f1a3e8b204
Revises: b7d4e2a15c8f
Create Date: 2026-07-15 18:40:00.000000

scan_type distinguishes 'quick' (passive-only) from 'full' (active VAPT).
user_id attributes a hosted scan to its owner (usage limits). Both are additive;
default 'full' + NULL user_id preserve local/self-hosted behavior.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


revision: str = 'c9f1a3e8b204'
down_revision: Union[str, None] = 'b7d4e2a15c8f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('scans', sa.Column('scan_type', sa.String(length=8),
                                     nullable=False, server_default='full'))
    op.add_column('scans', sa.Column('user_id', UUID(as_uuid=True), nullable=True))
    op.create_index('ix_scans_user_id', 'scans', ['user_id'])
    op.create_foreign_key('fk_scans_user_id', 'scans', 'users', ['user_id'], ['id'])


def downgrade() -> None:
    op.drop_constraint('fk_scans_user_id', 'scans', type_='foreignkey')
    op.drop_index('ix_scans_user_id', table_name='scans')
    op.drop_column('scans', 'user_id')
    op.drop_column('scans', 'scan_type')
