"""add awaiting_user_decision and cancelled to scanstatus enum

Revision ID: 61592c51b880
Revises: 6e16041d5a12
Create Date: 2026-07-02 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


revision: str = '61592c51b880'
down_revision: Union[str, None] = '6e16041d5a12'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Postgres 12+ allows ADD VALUE inside a transaction as long as the new
    # value isn't used in the same transaction - this migration only adds
    # the values, so a single execute per value is safe.
    op.execute("ALTER TYPE scanstatus ADD VALUE IF NOT EXISTS 'awaiting_user_decision'")
    op.execute("ALTER TYPE scanstatus ADD VALUE IF NOT EXISTS 'cancelled'")


def downgrade() -> None:
    # Postgres has no ALTER TYPE ... DROP VALUE - downgrading a native enum
    # requires rebuilding the type. Not needed here: nothing in this app
    # writes these values until the code that follows this migration ships,
    # so a downgrade only has to run before that point.
    pass
