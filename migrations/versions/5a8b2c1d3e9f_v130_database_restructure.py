"""v1.3.0 Database restructure - new tables and FK relationships

Revision ID: 5a8b2c1d3e9f
Revises: 16ff0ae3e3b2
Create Date: 2026-01-08

This migration adds:
- interfaces table (normalized from config_data JSONB)
- address_objects table
- service_objects table 
- vpn_tunnels table
- policy_interface_mappings table (N:M)
- policy_address_mappings table (N:M)
- policy_service_mappings table (N:M)
- allowed_access_alerts table
- server_exposures table
- interface_history table
- vdom_history table
- vdom_id FK to policies, log_entries, policy_history
- src_intf_id/dst_intf_id FKs to log_entries

Note: This migration supports multi-tenant architecture where some tables
only exist in tenant databases, not in the central database.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = '5a8b2c1d3e9f'
down_revision = '16ff0ae3e3b2'
branch_labels = None
depends_on = None


def table_exists(table_name):
    """Check if a table exists in the current database."""
    bind = op.get_bind()
    inspector = inspect(bind)
    return table_name in inspector.get_table_names()


def upgrade():
    # ========== NEW TABLES ==========
    
    # --- interfaces ---
    op.create_table('interfaces',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('vdom_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('alias', sa.String(100), nullable=True),
        sa.Column('type', sa.String(50), nullable=True),
        sa.Column('status', sa.String(20), nullable=True),
        sa.Column('ip_address', sa.String(50), nullable=True),
        sa.Column('netmask', sa.String(50), nullable=True),
        sa.Column('gateway', sa.String(50), nullable=True),
        sa.Column('vlan_id', sa.Integer(), nullable=True),
        sa.Column('role', sa.String(50), nullable=True),
        sa.Column('zone', sa.String(100), nullable=True),
        sa.Column('allowaccess', postgresql.JSONB(), nullable=True),
        sa.Column('speed', sa.String(50), nullable=True),
        sa.Column('config_data', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['device_id'], ['equipos.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['vdom_id'], ['vdoms.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('device_id', 'name', name='uq_device_interface')
    )
    op.create_index('ix_interfaces_device_id', 'interfaces', ['device_id'])
    op.create_index('ix_interfaces_vdom_id', 'interfaces', ['vdom_id'])
    op.create_index('ix_interfaces_name', 'interfaces', ['name'])

    # --- address_objects ---
    op.create_table('address_objects',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('vdom_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('type', sa.String(50), nullable=True),
        sa.Column('subnet', sa.String(100), nullable=True),
        sa.Column('start_ip', sa.String(50), nullable=True),
        sa.Column('end_ip', sa.String(50), nullable=True),
        sa.Column('fqdn', sa.String(255), nullable=True),
        sa.Column('country', sa.String(10), nullable=True),
        sa.Column('wildcard', sa.String(100), nullable=True),
        sa.Column('members', postgresql.JSONB(), nullable=True),
        sa.Column('associated_interface', sa.String(100), nullable=True),
        sa.Column('comments', sa.Text(), nullable=True),
        sa.Column('visibility', sa.String(20), nullable=True),
        sa.Column('config_data', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['device_id'], ['equipos.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['vdom_id'], ['vdoms.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('device_id', 'vdom_id', 'name', name='uq_device_vdom_address')
    )
    op.create_index('ix_address_objects_device_id', 'address_objects', ['device_id'])
    op.create_index('ix_address_objects_vdom_id', 'address_objects', ['vdom_id'])
    op.create_index('ix_address_objects_name', 'address_objects', ['name'])

    # --- service_objects ---
    op.create_table('service_objects',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('vdom_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('category', sa.String(100), nullable=True),
        sa.Column('protocol', sa.String(50), nullable=True),
        sa.Column('tcp_portrange', sa.String(255), nullable=True),
        sa.Column('udp_portrange', sa.String(255), nullable=True),
        sa.Column('sctp_portrange', sa.String(255), nullable=True),
        sa.Column('icmptype', sa.Integer(), nullable=True),
        sa.Column('icmpcode', sa.Integer(), nullable=True),
        sa.Column('protocol_number', sa.Integer(), nullable=True),
        sa.Column('is_group', sa.Boolean(), nullable=True),
        sa.Column('members', postgresql.JSONB(), nullable=True),
        sa.Column('visibility', sa.String(20), nullable=True),
        sa.Column('comments', sa.String(500), nullable=True),
        sa.Column('config_data', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['device_id'], ['equipos.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['vdom_id'], ['vdoms.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('device_id', 'vdom_id', 'name', name='uq_device_vdom_service')
    )
    op.create_index('ix_service_objects_device_id', 'service_objects', ['device_id'])
    op.create_index('ix_service_objects_vdom_id', 'service_objects', ['vdom_id'])
    op.create_index('ix_service_objects_name', 'service_objects', ['name'])

    # --- vpn_tunnels ---
    op.create_table('vpn_tunnels',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('vdom_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('type', sa.String(50), nullable=True),
        sa.Column('remote_gateway', sa.String(255), nullable=True),
        sa.Column('local_gateway', sa.String(50), nullable=True),
        sa.Column('interface', sa.String(100), nullable=True),
        sa.Column('interface_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('authmethod', sa.String(50), nullable=True),
        sa.Column('psk_key', sa.String(255), nullable=True),
        sa.Column('ike_version', sa.Integer(), nullable=True),
        sa.Column('mode', sa.String(20), nullable=True),
        sa.Column('proposals', postgresql.JSONB(), nullable=True),
        sa.Column('dpd', sa.String(20), nullable=True),
        sa.Column('dpd_retrycount', sa.Integer(), nullable=True),
        sa.Column('dpd_retryinterval', sa.Integer(), nullable=True),
        sa.Column('nattraversal', sa.String(20), nullable=True),
        sa.Column('phase2_settings', postgresql.JSONB(), nullable=True),
        sa.Column('status', sa.String(20), nullable=True),
        sa.Column('config_data', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['device_id'], ['equipos.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['vdom_id'], ['vdoms.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['interface_id'], ['interfaces.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('device_id', 'name', name='uq_device_vpn')
    )
    op.create_index('ix_vpn_tunnels_device_id', 'vpn_tunnels', ['device_id'])
    op.create_index('ix_vpn_tunnels_vdom_id', 'vpn_tunnels', ['vdom_id'])
    op.create_index('ix_vpn_tunnels_name', 'vpn_tunnels', ['name'])

    # --- policy_interface_mappings ---
    op.create_table('policy_interface_mappings',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('policy_uuid', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('interface_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('direction', sa.String(10), nullable=False),
        sa.ForeignKeyConstraint(['policy_uuid'], ['policies.uuid'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['interface_id'], ['interfaces.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('policy_uuid', 'interface_id', 'direction', name='uq_policy_interface_direction')
    )
    op.create_index('ix_policy_interface_mappings_policy_uuid', 'policy_interface_mappings', ['policy_uuid'])
    op.create_index('ix_policy_interface_mappings_interface_id', 'policy_interface_mappings', ['interface_id'])

    # --- policy_address_mappings ---
    op.create_table('policy_address_mappings',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('policy_uuid', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('address_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('direction', sa.String(10), nullable=False),
        sa.ForeignKeyConstraint(['policy_uuid'], ['policies.uuid'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['address_id'], ['address_objects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('policy_uuid', 'address_id', 'direction', name='uq_policy_address_direction')
    )
    op.create_index('ix_policy_address_mappings_policy_uuid', 'policy_address_mappings', ['policy_uuid'])
    op.create_index('ix_policy_address_mappings_address_id', 'policy_address_mappings', ['address_id'])

    # --- policy_service_mappings ---
    op.create_table('policy_service_mappings',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('policy_uuid', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('service_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(['policy_uuid'], ['policies.uuid'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['service_id'], ['service_objects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('policy_uuid', 'service_id', name='uq_policy_service')
    )
    op.create_index('ix_policy_service_mappings_policy_uuid', 'policy_service_mappings', ['policy_uuid'])
    op.create_index('ix_policy_service_mappings_service_id', 'policy_service_mappings', ['service_id'])

    # --- allowed_access_alerts ---
    op.create_table('allowed_access_alerts',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('interface_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('vdom_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('service', sa.String(50), nullable=False),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('interface_name', sa.String(100), nullable=True),
        sa.Column('interface_role', sa.String(50), nullable=True),
        sa.Column('interface_zone', sa.String(100), nullable=True),
        sa.Column('status', sa.String(20), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('acknowledged_at', sa.DateTime(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('resolved_by', sa.String(100), nullable=True),
        sa.ForeignKeyConstraint(['interface_id'], ['interfaces.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['device_id'], ['equipos.id']),
        sa.ForeignKeyConstraint(['vdom_id'], ['vdoms.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_allowed_access_alerts_interface_id', 'allowed_access_alerts', ['interface_id'])
    op.create_index('ix_allowed_access_alerts_device_id', 'allowed_access_alerts', ['device_id'])

    # --- server_exposures ---
    op.create_table('server_exposures',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('vdom_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('server_ip', sa.String(50), nullable=False),
        sa.Column('server_name', sa.String(255), nullable=True),
        sa.Column('internal_zone', sa.String(100), nullable=True),
        sa.Column('exposed_ports', postgresql.JSONB(), nullable=True),
        sa.Column('exposed_via_policies', postgresql.JSONB(), nullable=True),
        sa.Column('severity', sa.String(20), nullable=True),
        sa.Column('exposure_type', sa.String(50), nullable=True),
        sa.Column('log_count', sa.Integer(), nullable=True),
        sa.Column('external_ips_count', sa.Integer(), nullable=True),
        sa.Column('last_access', sa.DateTime(), nullable=True),
        sa.Column('first_seen', sa.DateTime(), nullable=True),
        sa.Column('status', sa.String(20), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('evidence', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['device_id'], ['equipos.id']),
        sa.ForeignKeyConstraint(['vdom_id'], ['vdoms.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_server_exposures_device_id', 'server_exposures', ['device_id'])
    op.create_index('ix_server_exposures_server_ip', 'server_exposures', ['server_ip'])

    # --- interface_history ---
    op.create_table('interface_history',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('interface_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('change_date', sa.DateTime(), nullable=False),
        sa.Column('change_type', sa.String(20), nullable=False),
        sa.Column('field_changed', sa.String(100), nullable=True),
        sa.Column('old_value', postgresql.JSONB(), nullable=True),
        sa.Column('new_value', postgresql.JSONB(), nullable=True),
        sa.Column('snapshot', postgresql.JSONB(), nullable=True),
        sa.ForeignKeyConstraint(['device_id'], ['equipos.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_interface_history_interface_id', 'interface_history', ['interface_id'])

    # --- vdom_history ---
    op.create_table('vdom_history',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('vdom_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('change_date', sa.DateTime(), nullable=False),
        sa.Column('change_type', sa.String(20), nullable=False),
        sa.Column('delta', postgresql.JSONB(), nullable=True),
        sa.Column('snapshot', postgresql.JSONB(), nullable=True),
        sa.ForeignKeyConstraint(['device_id'], ['equipos.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_vdom_history_vdom_id', 'vdom_history', ['vdom_id'])

    # ========== MODIFY EXISTING TABLES (conditionally for multi-tenant) ==========

    # --- policies: Add vdom_id FK (if policies table exists) ---
    if table_exists('policies'):
        op.add_column('policies', sa.Column('vdom_id', postgresql.UUID(as_uuid=True), nullable=True))
        op.create_index('ix_policies_vdom_id', 'policies', ['vdom_id'])
        if table_exists('vdoms'):
            op.create_foreign_key('fk_policies_vdom_id', 'policies', 'vdoms', ['vdom_id'], ['id'], ondelete='SET NULL')

    # --- log_entries: Add vdom_id, src_intf_id, dst_intf_id FKs (if log_entries table exists) ---
    if table_exists('log_entries'):
        op.add_column('log_entries', sa.Column('vdom_id', postgresql.UUID(as_uuid=True), nullable=True))
        op.add_column('log_entries', sa.Column('src_intf_id', postgresql.UUID(as_uuid=True), nullable=True))
        op.add_column('log_entries', sa.Column('dst_intf_id', postgresql.UUID(as_uuid=True), nullable=True))
        op.create_index('ix_log_entries_vdom_id', 'log_entries', ['vdom_id'])
        op.create_index('ix_log_entries_src_intf_id', 'log_entries', ['src_intf_id'])
        op.create_index('ix_log_entries_dst_intf_id', 'log_entries', ['dst_intf_id'])
        if table_exists('vdoms'):
            op.create_foreign_key('fk_log_entries_vdom_id', 'log_entries', 'vdoms', ['vdom_id'], ['id'], ondelete='SET NULL')
        if table_exists('interfaces'):
            op.create_foreign_key('fk_log_entries_src_intf_id', 'log_entries', 'interfaces', ['src_intf_id'], ['id'], ondelete='SET NULL')
            op.create_foreign_key('fk_log_entries_dst_intf_id', 'log_entries', 'interfaces', ['dst_intf_id'], ['id'], ondelete='SET NULL')

    # --- policy_history: Add vdom_id FK (if policy_history table exists) ---
    if table_exists('policy_history'):
        op.add_column('policy_history', sa.Column('vdom_id', postgresql.UUID(as_uuid=True), nullable=True))
        op.create_index('ix_policy_history_vdom_id', 'policy_history', ['vdom_id'])
        if table_exists('vdoms'):
            op.create_foreign_key('fk_policy_history_vdom_id', 'policy_history', 'vdoms', ['vdom_id'], ['id'], ondelete='SET NULL')


def downgrade():
    # ========== REVERT EXISTING TABLE MODIFICATIONS ==========
    
    # --- policy_history (if exists) ---
    if table_exists('policy_history'):
        try:
            op.drop_constraint('fk_policy_history_vdom_id', 'policy_history', type_='foreignkey')
        except:
            pass
        op.drop_index('ix_policy_history_vdom_id', table_name='policy_history')
        op.drop_column('policy_history', 'vdom_id')

    # --- log_entries (if exists) ---
    if table_exists('log_entries'):
        try:
            op.drop_constraint('fk_log_entries_dst_intf_id', 'log_entries', type_='foreignkey')
            op.drop_constraint('fk_log_entries_src_intf_id', 'log_entries', type_='foreignkey')
            op.drop_constraint('fk_log_entries_vdom_id', 'log_entries', type_='foreignkey')
        except:
            pass
        op.drop_index('ix_log_entries_dst_intf_id', table_name='log_entries')
        op.drop_index('ix_log_entries_src_intf_id', table_name='log_entries')
        op.drop_index('ix_log_entries_vdom_id', table_name='log_entries')
        op.drop_column('log_entries', 'dst_intf_id')
        op.drop_column('log_entries', 'src_intf_id')
        op.drop_column('log_entries', 'vdom_id')

    # --- policies (if exists) ---
    if table_exists('policies'):
        try:
            op.drop_constraint('fk_policies_vdom_id', 'policies', type_='foreignkey')
        except:
            pass
        op.drop_index('ix_policies_vdom_id', table_name='policies')
        op.drop_column('policies', 'vdom_id')

    # ========== DROP NEW TABLES (reverse order of creation) ==========
    
    op.drop_index('ix_vdom_history_vdom_id', table_name='vdom_history')
    op.drop_table('vdom_history')
    
    op.drop_index('ix_interface_history_interface_id', table_name='interface_history')
    op.drop_table('interface_history')
    
    op.drop_index('ix_server_exposures_server_ip', table_name='server_exposures')
    op.drop_index('ix_server_exposures_device_id', table_name='server_exposures')
    op.drop_table('server_exposures')
    
    op.drop_index('ix_allowed_access_alerts_device_id', table_name='allowed_access_alerts')
    op.drop_index('ix_allowed_access_alerts_interface_id', table_name='allowed_access_alerts')
    op.drop_table('allowed_access_alerts')
    
    op.drop_index('ix_policy_service_mappings_service_id', table_name='policy_service_mappings')
    op.drop_index('ix_policy_service_mappings_policy_uuid', table_name='policy_service_mappings')
    op.drop_table('policy_service_mappings')
    
    op.drop_index('ix_policy_address_mappings_address_id', table_name='policy_address_mappings')
    op.drop_index('ix_policy_address_mappings_policy_uuid', table_name='policy_address_mappings')
    op.drop_table('policy_address_mappings')
    
    op.drop_index('ix_policy_interface_mappings_interface_id', table_name='policy_interface_mappings')
    op.drop_index('ix_policy_interface_mappings_policy_uuid', table_name='policy_interface_mappings')
    op.drop_table('policy_interface_mappings')
    
    op.drop_index('ix_vpn_tunnels_name', table_name='vpn_tunnels')
    op.drop_index('ix_vpn_tunnels_vdom_id', table_name='vpn_tunnels')
    op.drop_index('ix_vpn_tunnels_device_id', table_name='vpn_tunnels')
    op.drop_table('vpn_tunnels')
    
    op.drop_index('ix_service_objects_name', table_name='service_objects')
    op.drop_index('ix_service_objects_vdom_id', table_name='service_objects')
    op.drop_index('ix_service_objects_device_id', table_name='service_objects')
    op.drop_table('service_objects')
    
    op.drop_index('ix_address_objects_name', table_name='address_objects')
    op.drop_index('ix_address_objects_vdom_id', table_name='address_objects')
    op.drop_index('ix_address_objects_device_id', table_name='address_objects')
    op.drop_table('address_objects')
    
    op.drop_index('ix_interfaces_name', table_name='interfaces')
    op.drop_index('ix_interfaces_vdom_id', table_name='interfaces')
    op.drop_index('ix_interfaces_device_id', table_name='interfaces')
    op.drop_table('interfaces')
