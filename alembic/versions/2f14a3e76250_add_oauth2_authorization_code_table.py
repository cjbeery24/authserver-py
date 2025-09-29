"""add_oauth2_authorization_code_table

Revision ID: 2f14a3e76250
Revises: b8db72cfb6d4
Create Date: 2025-09-22 08:27:17.370411

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '2f14a3e76250'
down_revision: Union[str, Sequence[str], None] = 'b8db72cfb6d4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Create oauth2_authorization_codes table
    op.create_table('oauth2_authorization_codes',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('client_id', sa.String(length=255), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('code', sa.String(length=255), nullable=False),
        sa.Column('redirect_uri', sa.Text(), nullable=False),
        sa.Column('scope', sa.Text(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('code_challenge', sa.Text(), nullable=True),
        sa.Column('code_challenge_method', sa.String(length=10), nullable=True),
        sa.ForeignKeyConstraint(['client_id'], ['oauth2_clients.client_id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes
    op.create_index('idx_oauth2_auth_code_client', 'oauth2_authorization_codes', ['client_id'], unique=False)
    op.create_index('idx_oauth2_auth_code_code', 'oauth2_authorization_codes', ['code'], unique=True)
    op.create_index('idx_oauth2_auth_code_expires', 'oauth2_authorization_codes', ['expires_at'], unique=False)
    op.create_index('idx_oauth2_auth_code_user', 'oauth2_authorization_codes', ['user_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    # Drop indexes
    op.drop_index('idx_oauth2_auth_code_user', table_name='oauth2_authorization_codes')
    op.drop_index('idx_oauth2_auth_code_expires', table_name='oauth2_authorization_codes')
    op.drop_index('idx_oauth2_auth_code_code', table_name='oauth2_authorization_codes')
    op.drop_index('idx_oauth2_auth_code_client', table_name='oauth2_authorization_codes')

    # Drop table
    op.drop_table('oauth2_authorization_codes')
