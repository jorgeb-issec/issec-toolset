from app import create_app
from app.extensions.db import db
from app.models.vdom import VDOM
from app.models.core import Company
from sqlalchemy import create_engine, text

app = create_app()

with app.app_context():
    companies = Company.query.all()
    print(f"Found {len(companies)} companies. Updating schemas for VDOMs table...")
    
    for company in companies:
        if not company.db_uri:
            continue
            
        print(f"Propagating to: {company.name}")
        
        try:
            engine = create_engine(company.db_uri)
            # Create Table
            VDOM.__table__.create(engine, checkfirst=True)
            print(f"  - Verified 'vdoms' table.")
            
            # Add config_data column
            with engine.connect() as conn:
                conn.execute(text("ALTER TABLE vdoms ADD COLUMN IF NOT EXISTS config_data JSONB;"))
                conn.commit()
                print(f"  - Verified 'config_data' column in 'vdoms'.")
            
        except Exception as e:
            print(f"  - Error: {e}")

    print("VDOM Schema update complete.")
