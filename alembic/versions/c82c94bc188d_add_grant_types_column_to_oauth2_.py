"""Add grant_types column to oauth2_clients table

Revision ID: c82c94bc188d
Revises: b0f1a6ba609b
Create Date: 2025-10-23 09:37:12.181742

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c82c94bc188d'
down_revision: Union[str, Sequence[str], None] = 'b0f1a6ba609b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Add grant_types column to oauth2_clients table
    op.add_column('oauth2_clients', sa.Column('grant_types', sa.Text(), nullable=False, server_default='["authorization_code", "refresh_token"]'))

    # Update existing clients to have default grant types
    op.execute("""
        UPDATE oauth2_clients
        SET grant_types = '["authorization_code", "refresh_token"]'
        WHERE grant_types IS NULL OR grant_types = '[]'
    """)


def downgrade() -> None:
    """Downgrade schema."""
    # Remove grant_types column from oauth2_clients table
    op.drop_column('oauth2_clients', 'grant_types')
