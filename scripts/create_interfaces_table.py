#!/usr/bin/env python3
"""
Schema Script: Create Interface Table in Tenant Databases

This script creates the 'interfaces' and 'interface_history' tables in all tenant databases.

Run from project root:
    python scripts/create_interfaces_table.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg2
from app import create_app
from app.extensions.db import db
from app.models.core import Company

CREATE_INTERFACES_TABLE = """
CREATE TABLE IF NOT EXISTS interfaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES equipos(id) ON DELETE CASCADE,
    vdom_id UUID REFERENCES vdoms(id) ON DELETE SET NULL,
    name VARCHAR(100) NOT NULL,
    alias VARCHAR(100),
    type VARCHAR(50),
    status VARCHAR(20) DEFAULT 'up',
    ip_address VARCHAR(50),
    netmask VARCHAR(50),
    gateway VARCHAR(50),
    vlan_id INTEGER,
    role VARCHAR(50),
    zone VARCHAR(100),
    allowaccess JSONB,
    speed VARCHAR(50),
    config_data JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP,
    CONSTRAINT uq_device_interface UNIQUE (device_id, name)
);

CREATE INDEX IF NOT EXISTS ix_interfaces_device_id ON interfaces(device_id);
CREATE INDEX IF NOT EXISTS ix_interfaces_vdom_id ON interfaces(vdom_id);
CREATE INDEX IF NOT EXISTS ix_interfaces_name ON interfaces(name);
"""

CREATE_INTERFACE_HISTORY_TABLE = """
CREATE TABLE IF NOT EXISTS interface_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    interface_id UUID NOT NULL,
    device_id UUID NOT NULL REFERENCES equipos(id) ON DELETE CASCADE,
    change_date TIMESTAMP DEFAULT NOW() NOT NULL,
    change_type VARCHAR(20) NOT NULL,
    field_changed VARCHAR(100),
    old_value JSONB,
    new_value JSONB,
    snapshot JSONB
);

CREATE INDEX IF NOT EXISTS ix_interface_history_interface_id ON interface_history(interface_id);
"""

def create_tables():
    app = create_app()
    
    with app.app_context():
        companies = Company.query.all()
        
        for company in companies:
            if not company.db_uri:
                print(f"[SKIP] {company.name}: No database URI")
                continue
            
            print(f"[PROCESSING] {company.name}")
            
            try:
                conn = psycopg2.connect(company.db_uri)
                conn.autocommit = True
                cur = conn.cursor()
                
                # Create interfaces table
                cur.execute(CREATE_INTERFACES_TABLE)
                print(f"  [OK] Created 'interfaces' table")
                
                # Create interface_history table
                cur.execute(CREATE_INTERFACE_HISTORY_TABLE)
                print(f"  [OK] Created 'interface_history' table")
                
                cur.close()
                conn.close()
                
            except Exception as e:
                print(f"  [ERROR] {company.name}: {str(e)}")
        
        print("\nTable creation complete.")

if __name__ == '__main__':
    create_tables()
