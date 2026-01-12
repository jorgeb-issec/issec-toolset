
from app import create_app
from app.extensions.db import db
from app.models.site import Site
from app.models.core import Company
from app.services.tenant_service import TenantService
from sqlalchemy import text
import sys

app = create_app()

def check_recovery():
    with app.app_context():
        print("=== Checking Main Database (Global Sites) ===")
        try:
            # Query using default session -> Main DB
            main_sites = db.session.query(Site).all()
            print(f"Found {len(main_sites)} sites in Main DB (Backup candidate):")
            for s in main_sites:
                print(f" - [{s.id}] {s.nombre}")
        except Exception as e:
            print(f"Error reading Main DB: {e}")
            return

        print("\n=== Checking Tenant Databases ===")
        companies = Company.query.all()
        for company in companies:
            print(f"\nTenant: {company.name} ({company.id})")
            try:
                engine = TenantService.get_engine(company.id)
                with engine.connect() as conn:
                    result = conn.execute(text("SELECT count(*) FROM sites")).scalar()
                    print(f" - Sites in Tenant DB: {result}")
            except Exception as e:
                print(f" - Error checking tenant {company.name}: {e}")

if __name__ == "__main__":
    check_recovery()
