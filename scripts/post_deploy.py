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
            
        # Migration 3: Add gemini_api_key to companies (Central DB only)
        if db_name == "Central DB":
            company_columns = [c['name'] for c in inspector.get_columns('companies')]
            if 'gemini_api_key' not in company_columns:
                print(f"    [+] Adding gemini_api_key column to companies...")
                with engine.connect() as conn:
                    conn.execute(text("ALTER TABLE companies ADD COLUMN gemini_api_key VARCHAR(255)"))
                    conn.commit()
                print(f"    ✓ gemini_api_key added")
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

        # Migration 4: Add status column to policies (v1.3.1)
        if 'policies' in tables:
            policy_cols = [c['name'] for c in inspector.get_columns('policies')]
            if 'status' not in policy_cols:
                print(f"    [+] Adding status column to policies...")
                with engine.connect() as conn:
                    conn.execute(text("ALTER TABLE policies ADD COLUMN status VARCHAR(20) DEFAULT 'enable'"))
                    conn.commit()
                print(f"    ✓ policies.status added")
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

def install_dependencies():
    """Install new dependencies from requirements.txt"""
    print("=== Checking Dependencies ===")
    try:
        import subprocess
        print("    [+] Installing/Updating dependencies via pip...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("    ✓ Dependencies updated")
    except Exception as e:
        print(f"    ✗ Error installing dependencies: {e}")
        # Don't exit, might be just a permission issue or offline, try to proceed

def ensure_log_tables(db_uri, db_name):
    """Ensure Log Analyzer tables exist in the database using explicit SQL"""
    
    engine = create_engine(db_uri)
    try:
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        created = 0
        
        with engine.connect() as conn:
            # 1. log_import_sessions table
            if 'log_import_sessions' not in tables:
                print(f"    [+] Creating table 'log_import_sessions'...")
                conn.execute(text("""
                    CREATE TABLE log_import_sessions (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        device_id UUID NOT NULL REFERENCES equipos(id) ON DELETE CASCADE,
                        filename VARCHAR(255),
                        imported_at TIMESTAMP DEFAULT NOW(),
                        log_count INTEGER DEFAULT 0,
                        start_date TIMESTAMP,
                        end_date TIMESTAMP,
                        stats JSONB
                    )
                """))
                conn.execute(text("CREATE INDEX idx_log_import_sessions_device ON log_import_sessions(device_id)"))
                created += 1
            
            # 2. log_entries table
            if 'log_entries' not in tables:
                print(f"    [+] Creating table 'log_entries'...")
                conn.execute(text("""
                    CREATE TABLE log_entries (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        device_id UUID REFERENCES equipos(id) ON DELETE CASCADE,
                        import_session_id UUID,
                        log_id VARCHAR(50),
                        log_type VARCHAR(50),
                        subtype VARCHAR(50),
                        level VARCHAR(20),
                        timestamp TIMESTAMP,
                        itime BIGINT,
                        eventtime BIGINT,
                        devid VARCHAR(50),
                        devname VARCHAR(100),
                        vdom VARCHAR(50),
                        src_intf VARCHAR(100),
                        src_intf_role VARCHAR(50),
                        src_ip VARCHAR(50),
                        src_port INTEGER,
                        src_country VARCHAR(100),
                        src_city VARCHAR(100),
                        src_mac VARCHAR(20),
                        dst_intf VARCHAR(100),
                        dst_intf_role VARCHAR(50),
                        dst_ip VARCHAR(50),
                        dst_port INTEGER,
                        dst_country VARCHAR(100),
                        dst_city VARCHAR(100),
                        policy_id INTEGER,
                        policy_uuid UUID REFERENCES policies(uuid) ON DELETE SET NULL,
                        policy_type VARCHAR(50),
                        action VARCHAR(50),
                        protocol INTEGER,
                        service VARCHAR(100),
                        app VARCHAR(100),
                        app_cat VARCHAR(100),
                        sent_bytes BIGINT,
                        rcvd_bytes BIGINT,
                        sent_pkts INTEGER,
                        rcvd_pkts INTEGER,
                        duration INTEGER,
                        session_id BIGINT,
                        nat_type VARCHAR(50),
                        threats JSONB,
                        threat_level VARCHAR(20),
                        raw_data JSONB,
                        created_at TIMESTAMP DEFAULT NOW()
                    )
                """))
                conn.execute(text("CREATE INDEX idx_log_entries_device ON log_entries(device_id)"))
                conn.execute(text("CREATE INDEX idx_log_entries_timestamp ON log_entries(timestamp)"))
                conn.execute(text("CREATE INDEX idx_log_entries_log_type ON log_entries(log_type)"))
                conn.execute(text("CREATE INDEX idx_log_entries_action ON log_entries(action)"))
                conn.execute(text("CREATE INDEX idx_log_entries_src_ip ON log_entries(src_ip)"))
                conn.execute(text("CREATE INDEX idx_log_entries_dst_ip ON log_entries(dst_ip)"))
                conn.execute(text("CREATE INDEX idx_log_entries_policy_id ON log_entries(policy_id)"))
                conn.execute(text("CREATE INDEX idx_log_entries_vdom ON log_entries(vdom)"))
                conn.execute(text("CREATE INDEX idx_log_entries_devid ON log_entries(devid)"))
                conn.execute(text("CREATE INDEX idx_log_entries_import_session ON log_entries(import_session_id)"))
                created += 1
            else:
                # Check if policy_uuid FK needs migration (from policies.id to policies.uuid)
                columns = {c['name']: c for c in inspector.get_columns('log_entries')}
                if 'policy_uuid' in columns:
                    col_type = str(columns['policy_uuid']['type']).upper()
                    if 'UUID' not in col_type:
                        print("    [!] policy_uuid is not UUID type. Migrating...")
                        conn.execute(text("ALTER TABLE log_entries DROP COLUMN policy_uuid"))
                        conn.execute(text("ALTER TABLE log_entries ADD COLUMN policy_uuid UUID REFERENCES policies(uuid) ON DELETE SET NULL"))
                        print("    ✓ Migrated policy_uuid to UUID with correct FK")
            
            # 3. security_recommendations table
            if 'security_recommendations' not in tables:
                print(f"    [+] Creating table 'security_recommendations'...")
                conn.execute(text("""
                    CREATE TABLE security_recommendations (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        device_id UUID REFERENCES equipos(id) ON DELETE CASCADE,
                        category VARCHAR(50),
                        severity VARCHAR(20),
                        title VARCHAR(255),
                        description TEXT,
                        recommendation TEXT,
                        related_policy_id INTEGER,
                        related_vdom VARCHAR(50),
                        evidence JSONB,
                        affected_count INTEGER,
                        status VARCHAR(20) DEFAULT 'open',
                        created_at TIMESTAMP DEFAULT NOW(),
                        resolved_at TIMESTAMP,
                        resolved_by VARCHAR(100)
                    )
                """))
                conn.execute(text("CREATE INDEX idx_security_recommendations_device ON security_recommendations(device_id)"))
                conn.execute(text("CREATE INDEX idx_security_recommendations_status ON security_recommendations(status)"))
                conn.execute(text("CREATE INDEX idx_security_recommendations_severity ON security_recommendations(severity)"))
                created += 1
            
            conn.commit()
        
        if created:
            print(f"    ✓ Created {created} Log Analyzer table(s)")
        else:
            print(f"    [=] Log Analyzer tables already exist")
            
        return created
    except Exception as e:
        print(f"    ✗ Error creating log tables: {e}")
        import traceback
        traceback.print_exc()
        return 0
    finally:
        engine.dispose()

def run_migrations():
    # 0. Install Dependencies first!
    install_dependencies()
    
    # Now safe to import app components
    from app import create_app
    from app.models.core import Company
    from app.extensions.db import db
    
    app = create_app()
    
    with app.app_context():
        print("\n=== ISSEC Post-Deploy Migration ===\n")
        
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
                # Standard migrations (columns)
                changes = migrate_database(company.db_uri, company.name)
                
                # Log Analyzer Tables
                changes += ensure_log_tables(company.db_uri, company.name)
                
                print(f"[{company.name}] Total schema changes: {changes}")
                
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
