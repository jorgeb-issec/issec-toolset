from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from app.models.core import Company
from app.extensions.db import db
import logging
import os
import re

logger = logging.getLogger(__name__)

class TenantService:
    _engines = {}

    @classmethod
    def get_engine(cls, company_id):
        """
        Retrieves or creates an SQLAlchemy engine for the specified company.
        """
        if str(company_id) in cls._engines:
            return cls._engines[str(company_id)]
        
        company = Company.query.get(company_id)
        if not company:
            logger.error(f"Company with ID {company_id} not found.")
            raise ValueError("Company not found")
        
        logger.info(f"Creating engine for company: {company.name}")
        engine = create_engine(company.db_uri)
        cls._engines[str(company_id)] = engine
        return engine

    @classmethod
    def get_session(cls, company_id):
        """
        Returns a new SQLAlchemy session bound to the company's database.
        Tips: The caller is responsible for closing this session!
        """
        engine = cls.get_engine(company_id)
        Session = sessionmaker(bind=engine)
        return Session()
    
    @classmethod
    def clear_engines(cls):
        """
        Disposes all cached engines. Useful for testing or reloads.
        """
        for engine in cls._engines.values():
            engine.dispose()
        cls._engines = {}

    @classmethod
    def create_tenant(cls, name, products):
        """
        Creates a new tenant: 
        1. Creates Postgres Database
        2. Creates Schema (Tables)
        3. Adds Company record
        """
        # 1. Sanitize Name for DB
        safe_name = re.sub(r'[^a-z0-9]', '_', name.lower())
        db_name = f"issec_tenant_{safe_name}"
        
        # Get Base URL (defaulting to env if not set, assuming we run in container/env)
        # We need to connect to 'postgres' db to create a new db
        base_url = os.environ.get('DATABASE_URL')
        if not base_url:
            raise ValueError("DATABASE_URL environment variable not set")
            
        # Parse URL to replace dbname with 'postgres'
        # Simple string manipulation for safety (assuming standard postgres:// format)
        if '/' in base_url.split('://')[1]:
            root_url = base_url.rsplit('/', 1)[0]
        else:
            root_url = base_url # Should not happen if valid SQLAlchemy URL
            
        postgres_url = f"{root_url}/postgres"
        
        # Connect to Postgres
        engine = create_engine(postgres_url, isolation_level="AUTOCOMMIT")
        with engine.connect() as conn:
            # Check if exists
            result = conn.execute(text(f"SELECT 1 FROM pg_database WHERE datname = '{db_name}'"))
            if result.fetchone():
                 logger.warning(f"Database {db_name} already exists. Skipping creation.")
            else:
                logger.info(f"Creating database {db_name}")
                conn.execute(text(f"CREATE DATABASE {db_name}"))
                
        # 2. Create Schema
        new_db_uri = f"{root_url}/{db_name}"
        tenant_engine = create_engine(new_db_uri)
        
        # Import models to ensure they are in metadata
        from app.models.policy import Policy
        from app.models.equipo import Equipo
        from app.models.site import Site
        # Create all tables in the new DB
        # Note: This creates ALL tables including 'users', 'companies' if they are in db.Model.metadata?
        # Yes, standard SQLAlchemy mixed usage. 
        # Ideally we filter, but for MVP providing full schema is okay (unused tables will just be empty).
        # Optimization: Create only specific tables.
        # But 'db' is shared. 
        # Let's create all for robustness unless it causes conflict.
        db.metadata.create_all(tenant_engine)
        
        # 3. Create Company Record
        new_company = Company(name=name, db_uri=new_db_uri, products=products)
        db.session.add(new_company)
        db.session.commit()
        
        logger.info(f"Tenant {name} created successfully.")
        return new_company

    @classmethod
    def delete_tenant(cls, company_id):
        """
        Deletes a tenant:
        1. Removes Company record
        2. Drops Postgres Database
        """
        company = Company.query.get(company_id)
        if not company:
            raise ValueError("Company not found")
            
        db_name = company.db_uri.rsplit('/', 1)[1]
        
        # Remove from Main DB first
        db.session.delete(company)
        db.session.commit()
        
        # Close connections if any
        if str(company_id) in cls._engines:
            cls._engines[str(company_id)].dispose()
            del cls._engines[str(company_id)]
            
        # Drop DB
        base_url = os.environ.get('DATABASE_URL')
        root_url = base_url.rsplit('/', 1)[0]
        postgres_url = f"{root_url}/postgres"
        
        engine = create_engine(postgres_url, isolation_level="AUTOCOMMIT")
        with engine.connect() as conn:
            # Terminate connections to the DB before dropping
            conn.execute(text(f"""
                SELECT pg_terminate_backend(pg_stat_activity.pid)
                FROM pg_stat_activity
                WHERE pg_stat_activity.datname = '{db_name}'
                AND pid <> pg_backend_pid();
            """))
            logger.info(f"Dropping database {db_name}")
            conn.execute(text(f"DROP DATABASE IF EXISTS {db_name}"))
