"""add_foreign_key_constraint_audit_log_user

Revision ID: 5001f6917f8e
Revises: 2f14a3e76250
Create Date: 2025-09-22 09:04:08.943255

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5001f6917f8e'
down_revision: Union[str, Sequence[str], None] = '2f14a3e76250'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Add foreign key constraint to audit_logs.user_id referencing users.id
    op.create_foreign_key(
        'fk_audit_logs_user_id',
        'audit_logs',
        'users',
        ['user_id'],
        ['id'],
        ondelete='SET NULL'  # Set to NULL if user is deleted
    )


def downgrade() -> None:
    """Downgrade schema."""
    # Drop the foreign key constraint
    op.drop_constraint('fk_audit_logs_user_id', 'audit_logs', type_='foreignkey')
