#!/usr/bin/env python3
"""
Post-deploy migration script for ISSEC Toolset
Run this after pulling new code from GitHub:
    python scripts/post_deploy.py

This script:
1. Adds missing columns to ALL tenant databases
2. Re-parses config_data for devices that have raw_config stored
"""
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text, create_engine, inspect
from sqlalchemy.orm import sessionmaker

def migrate_database(db_uri, db_name):
    """Apply migrations to a single database"""
    engine = create_engine(db_uri)
    
    try:
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        
        # Check if equipos table exists
        if 'equipos' not in tables:
            print(f"    [!] Table 'equipos' not found in {db_name}")
            return 0
        
        migrations_applied = 0
        
        # Migration 1: Add raw_config column if missing
        columns = [c['name'] for c in inspector.get_columns('equipos')]
        if 'raw_config' not in columns:
            print(f"    [+] Adding raw_config column...")
            with engine.connect() as conn:
                conn.execute(text("ALTER TABLE equipos ADD COLUMN raw_config TEXT"))
                conn.commit()
            print(f"    ✓ raw_config added")
            migrations_applied += 1
        
        # Migration 2: Create config_history table if missing
        if 'config_history' not in tables:
            print(f"    [+] Creating config_history table...")
            with engine.connect() as conn:
                conn.execute(text("""
                    CREATE TABLE config_history (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        device_id UUID NOT NULL REFERENCES equipos(id) ON DELETE CASCADE,
                        change_date TIMESTAMP DEFAULT NOW() NOT NULL,
                        change_type VARCHAR(20) NOT NULL,
                        raw_config TEXT,
                        config_data JSONB,
                        delta_summary JSONB
                    )
                """))
                conn.execute(text("CREATE INDEX idx_config_history_device ON config_history(device_id)"))
                conn.commit()
            print(f"    ✓ config_history table created")
            migrations_applied += 1
        
        return migrations_applied
        
    except Exception as e:
        print(f"    ✗ Error: {e}")
        return 0
    finally:
        engine.dispose()

def reparse_configs(db_uri, db_name):
    """Re-parse config_data for devices that have raw_config stored"""
    from app.services.config_parser import ConfigParserService
    
    engine = create_engine(db_uri)
    Session = sessionmaker(bind=engine)
    session = Session()
    
    try:
        # Find devices with raw_config but potentially outdated config_data
        result = session.execute(text("""
            SELECT id, raw_config FROM equipos 
            WHERE raw_config IS NOT NULL AND raw_config != ''
        """))
        
        devices = result.fetchall()
        if not devices:
            print(f"    [=] No devices with raw_config to re-parse")
            return 0
        
        updated = 0
        for device_id, raw_config in devices:
            try:
                # Re-parse with updated parser
                data = ConfigParserService.parse_config(raw_config)
                config_data = data.get('config_data', {})
                ha_config = config_data.get('ha', {})
                ha_enabled = ha_config.get('enabled', False)
                
                # Update device
                import json
                session.execute(
                    text("""
                        UPDATE equipos 
                        SET config_data = :config_data, ha_habilitado = :ha_enabled
                        WHERE id = :id
                    """),
                    {
                        'config_data': json.dumps(config_data),
                        'ha_enabled': ha_enabled,
                        'id': device_id
                    }
                )
                updated += 1
            except Exception as e:
                print(f"    [!] Error re-parsing device {device_id}: {e}")
        
        session.commit()
        if updated:
            print(f"    ✓ Re-parsed {updated} device(s) with updated VLAN/HA/allowaccess")
        return updated
        
    except Exception as e:
        print(f"    ✗ Error: {e}")
        session.rollback()
        return 0
    finally:
        session.close()
        engine.dispose()

def update_existing_configs(db_uri, db_name):
    """Update existing config_data to infer VLAN/vdom-link types from interface names"""
    import json
    import re
    
    engine = create_engine(db_uri)
    Session = sessionmaker(bind=engine)
    session = Session()
    
    try:
        # Get all devices
        result = session.execute(text("SELECT id, config_data FROM equipos WHERE config_data IS NOT NULL"))
        devices = result.fetchall()
        
        if not devices:
            return 0
        
        updated = 0
        for device_id, config_data in devices:
            if not config_data:
                continue
                
            # Parse existing config_data
            if isinstance(config_data, str):
                config = json.loads(config_data)
            else:
                config = config_data
            
            interfaces = config.get('interfaces', [])
            modified = False
            
            for intf in interfaces:
                name = intf.get('name', '').lower()
                current_type = intf.get('type', 'physical')
                
                # Infer VLAN from name patterns
                if current_type == 'physical':
                    # Check for vdom-link
                    if 'vdom-link' in name or 'vdomlink' in name:
                        intf['type'] = 'vdom-link'
                        modified = True
                    # Check for VLAN patterns: vlan100, vlan_50, port1.100, etc
                    elif re.match(r'.*vlan[_-]?\d+', name) or re.match(r'.*\.\d+$', name):
                        intf['type'] = 'vlan'
                        # Try to extract VLAN ID from name
                        vlan_match = re.search(r'vlan[_-]?(\d+)', name) or re.search(r'\.(\d+)$', name)
                        if vlan_match:
                            intf['vlan_id'] = int(vlan_match.group(1))
                        modified = True
                
                # Ensure new fields exist (even if empty)
                if 'allowaccess' not in intf:
                    intf['allowaccess'] = ''
                if 'vlan_id' not in intf:
                    intf['vlan_id'] = None
            
            if modified:
                session.execute(
                    text("UPDATE equipos SET config_data = :config_data WHERE id = :id"),
                    {'config_data': json.dumps(config), 'id': device_id}
                )
                updated += 1
        
        session.commit()
        if updated:
            print(f"    ✓ Inferred types for {updated} device(s) from interface names")
        else:
            print(f"    [=] No interface type updates needed")
        return updated
        
    except Exception as e:
        print(f"    ✗ Error updating configs: {e}")
        session.rollback()
        return 0
    finally:
        session.close()
        engine.dispose()

def sync_ha_from_config(db_uri, db_name):
    """Sync ha_habilitado column from config_data.ha.enabled"""
    import json
    
    engine = create_engine(db_uri)
    Session = sessionmaker(bind=engine)
    session = Session()
    
    try:
        result = session.execute(text("SELECT id, config_data, ha_habilitado FROM equipos WHERE config_data IS NOT NULL"))
        devices = result.fetchall()
        
        synced = 0
        for device_id, config_data, current_ha in devices:
            if not config_data:
                continue
            
            if isinstance(config_data, str):
                config = json.loads(config_data)
            else:
                config = config_data
            
            ha_config = config.get('ha', {})
            ha_enabled = ha_config.get('enabled', False)
            
            # Only update if different
            if ha_enabled != current_ha:
                session.execute(
                    text("UPDATE equipos SET ha_habilitado = :ha WHERE id = :id"),
                    {'ha': ha_enabled, 'id': device_id}
                )
                synced += 1
        
        session.commit()
        if synced:
            print(f"    ✓ Synced HA status for {synced} device(s)")
        else:
            print(f"    [=] HA status already in sync")
        return synced
        
    except Exception as e:
        print(f"    ✗ Error syncing HA: {e}")
        session.rollback()
        return 0
    finally:
        session.close()
        engine.dispose()

def run_migrations():
    from app import create_app
    from app.models.core import Company
    from app.extensions.db import db
    
    app = create_app()
    
    with app.app_context():
        print("=== ISSEC Post-Deploy Migration ===\n")
        
        # 1. Migrate central database first
        print("[Central DB] Checking migrations...")
        central_uri = os.environ.get('DATABASE_URL', app.config.get('SQLALCHEMY_DATABASE_URI'))
        total = migrate_database(central_uri, "Central DB")
        print(f"[Central DB] {total} changes applied\n")
        
        # 2. Migrate all tenant databases
        companies = Company.query.all()
        print(f"[Tenants] Found {len(companies)} companies\n")
        
        for company in companies:
            print(f"[{company.name}] Checking migrations...")
            if company.db_uri:
                changes = migrate_database(company.db_uri, company.name)
                print(f"[{company.name}] {changes} schema changes")
                
                # Re-parse configs if raw_config exists
                print(f"[{company.name}] Checking re-parse...")
                reparse_configs(company.db_uri, company.name)
                
                # Update existing configs by inferring types from names
                print(f"[{company.name}] Updating interface types...")
                update_existing_configs(company.db_uri, company.name)
                
                # Sync HA status from config_data
                print(f"[{company.name}] Syncing HA status...")
                sync_ha_from_config(company.db_uri, company.name)
                print()
            else:
                print(f"[{company.name}] No db_uri configured\n")
        
        print("=== Migration complete ===")

if __name__ == '__main__':
    run_migrations()
