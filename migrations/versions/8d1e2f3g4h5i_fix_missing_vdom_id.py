"""fix missing vdom_id in policy_history

Revision ID: 8d1e2f3g4h5i
Revises: 7c0d4e5f6g1h
Create Date: 2026-01-12

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '8d1e2f3g4h5i'
down_revision = '7c0d4e5f6g1h'
branch_labels = None
depends_on = None


def upgrade():
    """Add vdom_id to policy_history if missing"""
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = inspector.get_table_names()
    
    if 'policy_history' not in tables:
        return

    columns = [c['name'] for c in inspector.get_columns('policy_history')]
    
    if 'vdom_id' not in columns:
        print("Adding missing vdom_id column to policy_history")
        op.add_column('policy_history', sa.Column('vdom_id', postgresql.UUID(as_uuid=True), nullable=True))
        op.create_index('ix_policy_history_vdom_id', 'policy_history', ['vdom_id'])
        # Try to add FK, but wrap in try/except in case vdoms table clean
        try:
             op.create_foreign_key('fk_policy_history_vdom_id', 'policy_history', 'vdoms', ['vdom_id'], ['id'], ondelete='SET NULL')
        except Exception as e:
             print(f"Warning: Could not create FK for vdom_id: {e}")

def downgrade():
    """Remove vdom_id"""
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    columns = [c['name'] for c in inspector.get_columns('policy_history')]
    
    if 'vdom_id' in columns:
        op.drop_constraint('fk_policy_history_vdom_id', 'policy_history', type_='foreignkey')
        op.drop_index('ix_policy_history_vdom_id', table_name='policy_history')
        op.drop_column('policy_history', 'vdom_id')
