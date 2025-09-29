"""add_client_secret_rotation_tracking

Revision ID: 0efb8aad1742
Revises: 7b0fdc8e29d7
Create Date: 2025-09-22 09:31:27.765684

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0efb8aad1742'
down_revision: Union[str, Sequence[str], None] = '7b0fdc8e29d7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Add secret_last_rotated column to oauth2_clients table
    op.add_column('oauth2_clients', sa.Column('secret_last_rotated', sa.DateTime(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    # Remove secret_last_rotated column from oauth2_clients table
    op.drop_column('oauth2_clients', 'secret_last_rotated')
