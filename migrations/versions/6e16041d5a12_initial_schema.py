"""initial schema - scans and reports tables

Revision ID: 6e16041d5a12
Revises:
Create Date: 2026-06-30 09:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = '6e16041d5a12'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Do NOT call .create() explicitly here — the ENUM type used as a column
    # below already auto-creates itself via SQLAlchemy's before_create DDL
    # event when create_table() runs. Calling both was a genuine bug caught
    # during testing: it raised "type already exists" (DuplicateObject) on
    # the second, automatic creation attempt.
    scan_status = postgresql.ENUM(
        'queued', 'running', 'analysing', 'complete', 'failed',
        name='scanstatus',
    )

    op.create_table(
        'scans',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('domain', sa.String(length=255), nullable=False),
        sa.Column('status', scan_status, nullable=False),
        sa.Column('authorized', sa.Boolean(), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('module_statuses', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('raw_findings', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('ai_analysis', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('risk_score', sa.Integer(), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'reports',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('pdf_data', sa.LargeBinary(), nullable=False),
        sa.Column('generated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id']),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    op.drop_table('reports')
    op.drop_table('scans')

    scan_status = postgresql.ENUM(
        'queued', 'running', 'analysing', 'complete', 'failed',
        name='scanstatus',
    )
    scan_status.drop(op.get_bind(), checkfirst=True)
