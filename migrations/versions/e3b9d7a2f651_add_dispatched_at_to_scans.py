"""add dispatched_at to scans

Revision ID: e3b9d7a2f651
Revises: d4a8f1c6e390
Create Date: 2026-07-16 19:30:00.000000

Additive, nullable timestamp marking when a scan was handed to Celery. Backs the
hosted scan queue (config.HOSTED_QUEUE_ENABLED): a scan WAITING for capacity is
status='queued' AND dispatched_at IS NULL; a dispatched scan has it set and
occupies a concurrency slot until terminal. Fully backward-compatible - when the
flag is off (the self-hosted default) the column is never written or read and
stays NULL, so this migration changes no behavior for existing/open-source users.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e3b9d7a2f651'
down_revision: Union[str, None] = 'd4a8f1c6e390'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('scans', sa.Column('dispatched_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column('scans', 'dispatched_at')
