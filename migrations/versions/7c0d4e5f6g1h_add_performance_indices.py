"""add_performance_indices

Create performance indices for frequently queried columns

Revision ID: 7c0d4e5f6g1h
Revises: 6b9c3d4e5f0g
Create Date: 2026-01-12

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7c0d4e5f6g1h'
down_revision = '6b9c3d4e5f0g'
branch_labels = None
depends_on = None


def upgrade():
    """Add performance indices for commonly filtered columns"""
    
    # === LogEntry Indices === (Table: log_entries)
    # Index for device_id + timestamp (most common query pattern)
    op.create_index(
        'idx_logentry_device_timestamp',
        'log_entries',
        ['device_id', sa.text('timestamp DESC')],
        if_not_exists=True
    )
    
    # Index for action filtering (deny, accept stats)
    op.create_index(
        'idx_logentry_action',
        'log_entries',
        ['action'],
        if_not_exists=True
    )
    
    # Composite index for log stats GROUP BY queries
    op.create_index(
        'idx_logentry_device_action',
        'log_entries',
        ['device_id', 'action'],
        if_not_exists=True
    )
    
    # Index for VDOM filtering
    op.create_index(
        'idx_logentry_vdom',
        'log_entries',
        ['vdom'],
        if_not_exists=True
    )
    
    # === Policy Indices === (Table: policies)
    # Index for device_id + vdom (most common filter combo)
    op.create_index(
        'idx_policy_device_vdom',
        'policies',
        ['device_id', 'vdom'],
        if_not_exists=True
    )
    
    # Index for bytes_int (zero usage reports)
    op.create_index(
        'idx_policy_bytes',
        'policies',
        ['bytes_int'],
        if_not_exists=True
    )
    
    # Index for hit_count (zero hits reports)
    op.create_index(
        'idx_policy_hits',
        'policies',
        ['hit_count'],
        if_not_exists=True
    )
    
    # === SecurityRecommendation Indices === (Table: security_recommendations)
    # Index for device_id + status (common filtering)
    op.create_index(
        'idx_recommendation_device_status',
        'security_recommendations',
        ['device_id', 'status'],
        if_not_exists=True
    )
    
    # Index for severity ordering
    op.create_index(
        'idx_recommendation_severity',
        'security_recommendations',
        ['severity'],
        if_not_exists=True
    )
    
    # Index for category filtering
    op.create_index(
        'idx_recommendation_category',
        'security_recommendations',
        ['category'],
        if_not_exists=True
    )


def downgrade():
    """Remove performance indices"""
    # LogEntry
    op.drop_index('idx_logentry_device_timestamp', table_name='log_entries', if_exists=True)
    op.drop_index('idx_logentry_action', table_name='log_entries', if_exists=True)
    op.drop_index('idx_logentry_device_action', table_name='log_entries', if_exists=True)
    op.drop_index('idx_logentry_vdom', table_name='log_entries', if_exists=True)
    
    # Policy
    op.drop_index('idx_policy_device_vdom', table_name='policies', if_exists=True)
    op.drop_index('idx_policy_bytes', table_name='policies', if_exists=True)
    op.drop_index('idx_policy_hits', table_name='policies', if_exists=True)
    
    # SecurityRecommendation
    op.drop_index('idx_recommendation_device_status', table_name='security_recommendations', if_exists=True)
    op.drop_index('idx_recommendation_severity', table_name='security_recommendations', if_exists=True)
    op.drop_index('idx_recommendation_category', table_name='security_recommendations', if_exists=True)
