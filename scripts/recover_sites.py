import logging
import uuid
import sys
import os

# Add parent dir to path to find 'app'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from app.extensions.db import db
from app.models.core import Company
from app.models.site import Site
from app.services.tenant_service import TenantService
from sqlalchemy import text

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def recover_sites():
    app = create_app()
    with app.app_context():
        logger.info("Starting Site Recovery...")
        
        # 1. Get all companies
        companies = db.session.query(Company).all()
        
        recovered_count = 0
        
        for company in companies:
            logger.info(f"Checking Company: {company.name}")
            try:
                session = TenantService.get_session(company.id)
                
                # Get unique site_ids from equipments
                result = session.execute(text("SELECT DISTINCT site_id FROM equipos WHERE site_id IS NOT NULL"))
                rows = result.fetchall()
                
                for row in rows:
                    site_uuid_str = str(row[0])
                    try:
                        site_id = uuid.UUID(site_uuid_str)
                    except ValueError:
                        logger.warning(f"Invalid UUID in equipment: {site_uuid_str}")
                        continue
                        
                    # Check if Site exists in Main DB
                    existing_site = db.session.query(Site).get(site_id)
                    
                    if not existing_site:
                        logger.info(f"Found orphaned site_id {site_id}. Creating recovery record.")
                        
                        # Create Site
                        short_id = str(site_id)[:8]
                        site_name = f"Site-Recovered-{short_id}"
                        
                        # Handle name collision unlikely for UUID but checking
                        if db.session.query(Site).filter_by(nombre=site_name).first():
                             site_name = f"Site-Recovered-{short_id}-{uuid.uuid4().hex[:4]}"

                        new_site = Site(
                            id=site_id, # Preserve the UUID so links work
                            nombre=site_name,
                            direccion="Recovered by System"
                        )
                        db.session.add(new_site)
                        recovered_count += 1
                        
                session.close()
                
            except Exception as e:
                logger.error(f"Error processing company {company.name}: {e}")
        
        if recovered_count > 0:
            db.session.commit()
            logger.info(f"Successfully recovered {recovered_count} sites.")
        else:
            logger.info("No orphaned sites found.")

if __name__ == "__main__":
    recover_sites()
