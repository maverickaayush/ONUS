"""add updated_at to scans

Revision ID: 5c200e4261e5
Revises: 61592c51b880
Create Date: 2026-07-07 08:49:07.481935

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '5c200e4261e5'
down_revision: Union[str, None] = '61592c51b880'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('scans', sa.Column('updated_at', sa.DateTime(), nullable=True))
    # Backfill existing rows so the /api/scans listing page's "Last updated"
    # column has a sensible value immediately, instead of every pre-existing
    # scan showing blank until its next write.
    op.execute("UPDATE scans SET updated_at = created_at WHERE updated_at IS NULL")


def downgrade() -> None:
    op.drop_column('scans', 'updated_at')
