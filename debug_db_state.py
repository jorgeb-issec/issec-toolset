import sys
import os
from sqlalchemy import text

# Add app to path
sys.path.append(os.getcwd())

from app import create_app
from app.extensions.db import db
from app.models.policy import Policy
from app.models.log_entry import LogEntry
from app.models.equipo import Equipo
from app.models.core import Company

app = create_app()

with app.app_context():
    # 1. Get Tenant DB
    # We need to find a tenant with data. Let's list companies.
    companies = db.session.query(Company).all()
    
    for comp in companies:
        print(f"Checking Company: {comp.name}")
        
        db_uri = comp.db_uri
        if not db_uri:
             print("  No DB URI.")
             continue
             
        if not db_uri:
            print("  No DB URI.")
            continue
            
        print(f"  DB URI: {db_uri}")
             
        # Create a temporary engine/session
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        
        engine = create_engine(db_uri)
        Session = sessionmaker(bind=engine)
        t_session = Session()
        
        try:
            # Query EQUIPOS table in Tenant DB directly
            # We need to define a minimal model or use reflection, or just raw SQL?
            # Using existing models might work if they are bound to this session, 
            # but usually models are bound to the global 'db'.
            # Safer to use the model classes but bound to this session.
            
            devices = t_session.query(Equipo).all()
            print(f"  Devices (in Tenant DB): {[d.nombre for d in devices]}")

            for dev in devices:
                p_count = t_session.query(Policy).filter_by(device_id=dev.id).count()
                l_count = t_session.query(LogEntry).filter_by(device_id=dev.id).count()
                print(f"    Device {dev.nombre} (ID: {dev.id}):")
                print(f"      Policies: {p_count}")
                print(f"      Logs:     {l_count}")
                
                if p_count > 0:
                     # Sample detection
                     from sqlalchemy import func
                     zombies = t_session.query(Policy).filter(Policy.device_id==dev.id, func.lower(Policy.status)=='enable').count()
                     print(f"      Enabled Policies (Lower check): {zombies}")
                     
                     # Check recommendations
                     from app.models.security_recommendation import SecurityRecommendation
                     
                     recs = t_session.query(
                         SecurityRecommendation.category,
                         SecurityRecommendation.severity,
                         func.count(SecurityRecommendation.id)
                     ).filter_by(device_id=dev.id).group_by(SecurityRecommendation.category, SecurityRecommendation.severity).all()
                     
                     print("      Recommendations found:")
                     total_r = 0
                     for cat, sev, count in recs:
                         print(f"        - [{cat} | {sev}]: {count}")
                         total_r += count
                     
                     if total_r > 0:
                         # Show a few titles to identify them
                         samples = t_session.query(SecurityRecommendation.title).filter_by(device_id=dev.id).limit(5).all()
                         print(f"        Samples: {[s[0] for s in samples]}")
                         
                         # Check status
                         open_recs = t_session.query(SecurityRecommendation).filter_by(device_id=dev.id, status='open').count()
                         print(f"        Open recommendations: {open_recs}")

        except Exception as e:
            print(f"    Error querying tenant DB: {e}")
        finally:
            t_session.close()
