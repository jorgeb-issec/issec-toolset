"""add topology to site

Revision ID: 6b9c3d4e5f0g
Revises: 5a8b2c1d3e9f
Create Date: 2026-01-08 15:45:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '6b9c3d4e5f0g'
down_revision = '5a8b2c1d3e9f'
branch_labels = None
depends_on = None


def upgrade():
    # Helper to check if column exists before adding (for idempotency)
    # But Alembic usually assumes state. 
    # We'll use a safer approach checking connection
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = [c['name'] for c in inspector.get_columns('sites')]
    
    if 'topology_data' not in columns:
        op.add_column('sites', sa.Column('topology_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade():
    op.drop_column('sites', 'topology_data')
