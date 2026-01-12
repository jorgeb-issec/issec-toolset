import os
import sys
from sqlalchemy import create_engine, text, inspect
from dotenv import load_dotenv

# Add parent directory to path to ensure we can import if needed, 
# though for this script we just need the DB URI
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

load_dotenv()

def fix_sites_schema():
    print("=== ISSEC Schema Fix for 'sites.topology_data' ===")
    
    db_uri = os.environ.get('DATABASE_URL')
    if not db_uri:
        # Fallback to config if not in env
        try:
            from app.config import Config
            db_uri = Config.SQLALCHEMY_DATABASE_URI
        except ImportError:
            pass
            
    if not db_uri:
        print("[-] Error: Could not find DATABASE_URL environment variable.")
        return

    print(f"[+] Connecting to database...")
    engine = create_engine(db_uri)
    
    try:
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        
        if 'sites' not in tables:
            print("[-] Table 'sites' does not exist in this database.")
            return

        cols = [c['name'] for c in inspector.get_columns('sites')]
        
        if 'topology_data' in cols:
            print("[+] Column 'topology_data' ALREADY EXISTS in 'sites' table.")
            print("[=] No action needed.")
        else:
            print("[!] Column 'topology_data' MISSING using 'sites' table.")
            print("[+] Adding column 'topology_data' (JSONB)...")
            with engine.connect() as conn:
                conn.execute(text("ALTER TABLE sites ADD COLUMN topology_data JSONB"))
                conn.commit()
            print("[✓] Successfully added 'topology_data' column.")
            
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        engine.dispose()

if __name__ == "__main__":
    fix_sites_schema()
