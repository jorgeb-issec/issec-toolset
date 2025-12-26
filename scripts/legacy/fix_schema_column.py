from flask import Flask
from app.config import Config
from app.extensions.db import db
from app.models.core import Company
from sqlalchemy import create_engine, text, inspect

def fix_schema():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)

    with app.app_context():
        # Clean session to avoid stale data
        db.session.remove()
        companies = Company.query.filter_by(is_active=True).all()
        for company in companies:
            print(f"Checking schema for company: {company.name}...")
            try:
                # Get Engine directly using URI
                engine = create_engine(company.db_uri)
                
                # Use Inspection to avoid errors
                insp = inspect(engine)
                columns = [c['name'] for c in insp.get_columns('equipos')]
                
                if 'config_data' not in columns:
                    print(f"  - 'config_data' column MISSING. Adding it...")
                    with engine.connect() as conn:
                        conn.execute(text("ALTER TABLE equipos ADD COLUMN config_data JSONB;"))
                        conn.commit()
                    print(f"  - FIXED.")
                else:
                    print(f"  - 'config_data' column already exists.")
                    
            except Exception as e:
                print(f"  - CRITICAL ERROR for {company.name}: {e}")

if __name__ == "__main__":
    fix_schema()
