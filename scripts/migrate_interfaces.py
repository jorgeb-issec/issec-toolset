#!/usr/bin/env python3
"""
Migration Script: Populate Interface Table from Existing Device config_data

This script reads config_data.interfaces from all Equipo records and creates
corresponding entries in the interfaces table for topology visualization.

Run from project root:
    python scripts/migrate_interfaces.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.extensions.db import db
from app.models.core import Company
from app.models.equipo import Equipo
from app.models.vdom import VDOM
from app.models.interface import Interface
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

def migrate_interfaces():
    app = create_app()
    
    with app.app_context():
        # Get all companies (tenants)
        companies = Company.query.all()
        
        total_interfaces_created = 0
        
        for company in companies:
            if not company.db_uri:
                print(f"[SKIP] {company.name}: No database URI")
                continue
            
            print(f"\n[PROCESSING] {company.name}")
            
            try:
                # Connect to tenant database
                engine = create_engine(company.db_uri)
                Session = sessionmaker(bind=engine)
                session = Session()
                
                # Get all devices with config_data
                devices = session.query(Equipo).filter(
                    Equipo.config_data.isnot(None)
                ).all()
                
                for device in devices:
                    config_data = device.config_data or {}
                    interfaces = config_data.get('interfaces', [])
                    
                    if not interfaces:
                        print(f"  [SKIP] {device.nombre}: No interfaces in config_data")
                        continue
                    
                    # Build VDOM name->id map
                    vdom_map = {}
                    for vdom_obj in session.query(VDOM).filter_by(device_id=device.id).all():
                        vdom_map[vdom_obj.name] = vdom_obj.id
                    
                    interfaces_created = 0
                    
                    for intf_data in interfaces:
                        intf_name = intf_data.get('name')
                        if not intf_name:
                            continue
                        
                        # Check if already exists
                        existing = session.query(Interface).filter_by(
                            device_id=device.id,
                            name=intf_name
                        ).first()
                        
                        if existing:
                            continue
                        
                        # Get VDOM ID
                        intf_vdom_name = intf_data.get('vdom', 'root')
                        vdom_id = vdom_map.get(intf_vdom_name)
                        
                        # Parse allowaccess
                        allowaccess = intf_data.get('allowaccess', '')
                        if isinstance(allowaccess, str):
                            allowaccess = allowaccess.split() if allowaccess else []
                        
                        new_intf = Interface(
                            device_id=device.id,
                            vdom_id=vdom_id,
                            name=intf_name,
                            alias=intf_data.get('alias'),
                            type=intf_data.get('type', 'physical'),
                            status=intf_data.get('status', 'up'),
                            ip_address=intf_data.get('ip'),
                            role=intf_data.get('role', 'undefined'),
                            vlan_id=intf_data.get('vlan_id'),
                            allowaccess=allowaccess,
                            config_data=intf_data
                        )
                        session.add(new_intf)
                        interfaces_created += 1
                    
                    if interfaces_created > 0:
                        print(f"  [OK] {device.nombre}: Created {interfaces_created} interfaces")
                        total_interfaces_created += interfaces_created
                
                session.commit()
                session.close()
                engine.dispose()
                
            except Exception as e:
                print(f"  [ERROR] {company.name}: {str(e)}")
        
        print(f"\n{'='*50}")
        print(f"Migration complete. Total interfaces created: {total_interfaces_created}")

if __name__ == '__main__':
    migrate_interfaces()
