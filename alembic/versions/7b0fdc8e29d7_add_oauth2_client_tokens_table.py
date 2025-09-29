"""add_oauth2_client_tokens_table

Revision ID: 7b0fdc8e29d7
Revises: 5001f6917f8e
Create Date: 2025-09-22 09:13:05.716519

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7b0fdc8e29d7'
down_revision: Union[str, Sequence[str], None] = '5001f6917f8e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Create oauth2_client_tokens table
    op.create_table('oauth2_client_tokens',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('client_id', sa.Integer(), nullable=False),
        sa.Column('token', sa.String(length=255), nullable=False),
        sa.Column('token_type', sa.String(length=50), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['client_id'], ['oauth2_clients.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes
    op.create_index('idx_oauth2_client_token_client', 'oauth2_client_tokens', ['client_id'], unique=False)
    op.create_index('idx_oauth2_client_token_type', 'oauth2_client_tokens', ['token_type'], unique=False)
    op.create_index('idx_oauth2_client_token_expires', 'oauth2_client_tokens', ['expires_at'], unique=False)
    op.create_index('idx_oauth2_client_token_token', 'oauth2_client_tokens', ['token'], unique=True)


def downgrade() -> None:
    """Downgrade schema."""
    # Drop indexes
    op.drop_index('idx_oauth2_client_token_token', table_name='oauth2_client_tokens')
    op.drop_index('idx_oauth2_client_token_expires', table_name='oauth2_client_tokens')
    op.drop_index('idx_oauth2_client_token_type', table_name='oauth2_client_tokens')
    op.drop_index('idx_oauth2_client_token_client', table_name='oauth2_client_tokens')

    # Drop table
    op.drop_table('oauth2_client_tokens')
