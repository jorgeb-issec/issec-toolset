"""
Test script to run analyzers directly and verify output.
"""
import sys
import os
sys.path.insert(0, os.getcwd())

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import uuid

from app import create_app
from app.extensions.db import db
from app.models.core import Company
from app.models.equipo import Equipo
from app.services.dynamic_analyzer import DynamicAnalyzer
from app.services.static_analyzer import StaticAnalyzer
from app.services.vdom_analyzer import VDOMAnalyzer

app = create_app()

with app.app_context():
    companies = db.session.query(Company).all()
    
    for comp in companies:
        print(f"\n{'='*60}")
        print(f"COMPANY: {comp.name}")
        print(f"{'='*60}")
        
        db_uri = comp.db_uri
        if not db_uri:
            continue
        
        engine = create_engine(db_uri)
        Session = sessionmaker(bind=engine)
        session = Session()
        
        try:
            devices = session.query(Equipo).limit(1).all()  # Just test one device
            
            for dev in devices:
                print(f"\nTesting Device: {dev.nombre} (ID: {dev.id})")
                device_id = dev.id  # This is already a UUID object
                
                print("\n--- STATIC ANALYZER ---")
                try:
                    static_recs = StaticAnalyzer.analyze_device(device_id, session=session)
                    print(f"  Generated: {len(static_recs)} recommendations")
                    for r in static_recs[:3]:
                        print(f"    - [{r.get('severity')}] {r.get('title')}")
                except Exception as e:
                    print(f"  ERROR: {e}")
                    import traceback
                    traceback.print_exc()
                
                print("\n--- DYNAMIC ANALYZER ---")
                try:
                    # Don't commit to DB, just test generation
                    dynamic_recs = DynamicAnalyzer.detect_zombies(device_id, 30, session)
                    print(f"  Zombies: {len(dynamic_recs)}")
                    
                    ztna_recs = DynamicAnalyzer.analyze_least_privilege(device_id, 30, session)
                    print(f"  ZTNA proposals: {len(ztna_recs)}")
                    
                    for r in dynamic_recs[:2]:
                        print(f"    - [{r.severity}] {r.title}")
                    for r in ztna_recs[:2]:
                        print(f"    - [{r.severity}] {r.title}")
                except Exception as e:
                    print(f"  ERROR: {e}")
                    import traceback
                    traceback.print_exc()
                
                print("\n--- VDOM ANALYZER ---")
                try:
                    vdom_recs = VDOMAnalyzer.analyze_device(device_id, session=session)
                    print(f"  Generated: {len(vdom_recs)} recommendations")
                    for r in vdom_recs[:3]:
                        print(f"    - [{r.severity}] {r.title}")
                except Exception as e:
                    print(f"  ERROR: {e}")
                    import traceback
                    traceback.print_exc()
                    
        except Exception as e:
            print(f"  ERROR: {e}")
            import traceback
            traceback.print_exc()
        finally:
            session.rollback()  # Don't persist anything
            session.close()
