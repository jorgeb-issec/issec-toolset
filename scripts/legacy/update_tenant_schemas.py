from app import create_app
from app.extensions.db import db
from app.models.history import PolicyHistory
# Ensure other models are loaded
from app.models.core import Company, Role
from app.models.site import Site
from app.models.equipo import Equipo
from app.models.policy import Policy
from sqlalchemy import create_engine, text

app = create_app()

with app.app_context():
    companies = Company.query.all()
    print(f"Found {len(companies)} companies.")
    
    for company in companies:
        if not company.db_uri:
            continue
            
        print(f"Updating schema for company: {company.name}")
        
        try:
            # Use create_engine directly
            engine = create_engine(company.db_uri)
            
            # Create tables
            # We use the metadata from PolicyHistory to create just that table
            # Or simpler: db.metadata.create_all(bind=engine) but that might try to create existing.
            # Safe way for single table:
            PolicyHistory.__table__.create(engine, checkfirst=True)
            print(f"  - Created policy_history table if not exists.")
            
            # 2. Add config_data to active companies if misses
            # Using raw SQL to be safe if table exists
            with engine.connect() as conn:
                conn.execute(text("ALTER TABLE equipos ADD COLUMN IF NOT EXISTS config_data JSONB;"))
                conn.commit()
                print(f"  - Added config_data column to equipos.")
                
        except Exception as e:
            print(f"  - Error: {e}")

    print("Schema update complete.")
