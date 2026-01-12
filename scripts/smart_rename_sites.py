import logging
import sys
import os
from sqlalchemy import text

# Add parent dir to path to find 'app'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from app.extensions.db import db
from app.models.site import Site
from app.models.equipo import Equipo
from app.services.tenant_service import TenantService
from app.models.core import Company

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def smart_rename():
    app = create_app()
    with app.app_context():
        logger.info("Starting Smart Site Renaming...")
        
        # 1. Find all "Recovered" sites
        recovered_sites = db.session.query(Site).filter(Site.nombre.like('Site-Recovered-%')).all()
        
        if not recovered_sites:
            logger.info("No 'Site-Recovered-*' sites found. Nothing to rename.")
            return

        logger.info(f"Found {len(recovered_sites)} recovered sites to check.")
        
        companies = db.session.query(Company).all()
        
        for site in recovered_sites:
            # We need to find which tenant has devices for this site to get a name
            # This is inefficient (checking all tenants) but robust for this one-off script
            
            new_name = None
            found_device = False
            
            for company in companies:
                try:
                    session = TenantService.get_session(company.id)
                    # Find ANY device in this site
                    device = session.query(Equipo).filter(Equipo.site_id == site.id).first()
                    
                    if device:
                        # Construct new name from device info
                        base_name = device.hostname or device.nombre
                        # Clean name
                        base_name = base_name.split('.')[0] # remove domain if present
                        new_name = f"Site-{base_name}"
                        found_device = True
                        session.close()
                        break # Found a device, stop looking in other tenants
                    
                    session.close()
                except Exception as e:
                    logger.warning(f"Skipping company {company.name}: {e}")
            
            if found_device and new_name:
                # Check for collision in Main DB
                collision = db.session.query(Site).filter(Site.nombre == new_name).first()
                if collision and collision.id != site.id:
                    new_name = f"{new_name}-{str(site.id)[:4]}"
                
                logger.info(f"Renaming '{site.nombre}' -> '{new_name}'")
                site.nombre = new_name
                site.direccion = "Auto-renamed based on Device Hostname"
            else:
                logger.warning(f"Could not find devices for site {site.nombre} (ID: {site.id}) in any active tenant.")

        db.session.commit()
        logger.info("Renaming complete.")

if __name__ == "__main__":
    smart_rename()
