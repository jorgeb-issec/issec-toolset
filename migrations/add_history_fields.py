"""Add vdom and import_session_id to policy_history

Revision ID: add_history_fields
Revises: 
Create Date: 2025-12-16 10:40:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'add_history_fields'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Add new columns to policy_history table
    op.add_column('policy_history', sa.Column('vdom', sa.String(length=50), nullable=True))
    op.add_column('policy_history', sa.Column('import_session_id', postgresql.UUID(as_uuid=True), nullable=True))
    
    # Create indexes for better query performance
    op.create_index(op.f('ix_policy_history_vdom'), 'policy_history', ['vdom'], unique=False)
    op.create_index(op.f('ix_policy_history_import_session_id'), 'policy_history', ['import_session_id'], unique=False)
    
    # Update existing records to have a vdom (you may need to customize this based on your data)
    # For now, we'll set them to 'root' as a default
    op.execute("UPDATE policy_history SET vdom = 'root' WHERE vdom IS NULL")
    
    # Make vdom NOT NULL after setting default values
    op.alter_column('policy_history', 'vdom', nullable=False)


def downgrade():
    # Remove indexes
    op.drop_index(op.f('ix_policy_history_import_session_id'), table_name='policy_history')
    op.drop_index(op.f('ix_policy_history_vdom'), table_name='policy_history')
    
    # Remove columns
    op.drop_column('policy_history', 'import_session_id')
    op.drop_column('policy_history', 'vdom')
