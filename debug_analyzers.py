"""
Diagnostic script to test analyzer queries directly.
"""
import sys
import os
sys.path.insert(0, os.getcwd())

from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker

from app import create_app
from app.extensions.db import db
from app.models.core import Company
from app.models.policy import Policy
from app.models.log_entry import LogEntry
from app.models.vdom import VDOM
from app.models.interface import Interface
from app.models.equipo import Equipo

app = create_app()

with app.app_context():
    companies = db.session.query(Company).all()
    
    for comp in companies:
        print(f"\n{'='*60}")
        print(f"COMPANY: {comp.name}")
        print(f"{'='*60}")
        
        db_uri = comp.db_uri
        if not db_uri:
            print("  No DB URI - skipping")
            continue
        
        engine = create_engine(db_uri)
        Session = sessionmaker(bind=engine)
        session = Session()
        
        try:
            # 1. Count Devices
            devices = session.query(Equipo).all()
            print(f"\nDevices: {len(devices)}")
            
            for dev in devices:
                print(f"\n  Device: {dev.nombre} (ID: {dev.id})")
                
                # 2. Count Policies
                total_policies = session.query(Policy).filter_by(device_id=dev.id).count()
                print(f"    Total Policies: {total_policies}")
                
                # 3. Check Policy Status distribution
                status_dist = session.query(
                    Policy.status, func.count(Policy.uuid)
                ).filter_by(device_id=dev.id).group_by(Policy.status).all()
                print(f"    Status Distribution: {dict(status_dist)}")
                
                # 4. Check enabled policies (case insensitive)
                enabled = session.query(Policy).filter(
                    Policy.device_id == dev.id,
                    func.lower(Policy.status) == 'enable'
                ).count()
                print(f"    Enabled Policies (lower check): {enabled}")
                
                # 5. Check for ANY open policies (ZTNA candidates)
                open_policies = session.query(Policy).filter(
                    Policy.device_id == dev.id,
                    func.lower(Policy.action) == 'accept'
                ).all()
                
                any_count = 0
                for p in open_policies:
                    src = (p.src_addr or '').lower()
                    dst = (p.dst_addr or '').lower()
                    svc = (p.service or '').lower()
                    if 'all' in src or 'all' in dst or 'all' in svc or '0.0.0.0' in src or '0.0.0.0' in dst:
                        any_count += 1
                        if any_count <= 3:
                            print(f"      Open Policy Sample: ID={p.policy_id}, Src={p.src_addr}, Dst={p.dst_addr}, Svc={p.service}")
                
                print(f"    Open/ANY Policies: {any_count}")
                
                # 6. Check Logs
                log_count = session.query(LogEntry).filter_by(device_id=dev.id).count()
                print(f"    Log Entries: {log_count}")
                
                # 7. Check VDOMs
                vdom_count = session.query(VDOM).filter_by(device_id=dev.id).count()
                print(f"    VDOMs: {vdom_count}")
                
                # 8. Check Interfaces
                intf_count = session.query(Interface).filter_by(device_id=dev.id).count()
                print(f"    Interfaces: {intf_count}")
                
        except Exception as e:
            print(f"  ERROR: {e}")
            import traceback
            traceback.print_exc()
        finally:
            session.close()
