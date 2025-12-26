from app import create_app
from app.extensions.db import db
from app.models.core import Role, UserCompanyRole, Company
from app.models.user import User

app = create_app()

with app.app_context():
    print("Dropping tables (UserCompanyRole, Role, User)...")
    # Drop in order of dependency
    UserCompanyRole.__table__.drop(db.engine)
    Role.__table__.drop(db.engine)
    User.__table__.drop(db.engine)
    Company.__table__.drop(db.engine)
    
    print("Recreating tables...")
    db.create_all()
    
    print("Seeding default roles...")
    # Create Default Roles
    admin_perms = {
        "global_admin": True,
        "manage_tenants": True, 
        "manage_users": True,
        "manage_roles": True,
        "access_policy_explorer": True,
        "access_log_analyzer": True
    }
    
    role_admin = Role(name='Admin', description='Global Administrator', permissions=admin_perms)
    db.session.add(role_admin)
    
    # Analyst Role
    analyst_perms = {
        "access_policy_explorer": True,
        "access_log_analyzer": True
    }
    role_analyst = Role(name='Analyst', description='Security Analyst', permissions=analyst_perms)
    db.session.add(role_analyst)
    
    # Viewer Role
    viewer_perms = {
        "access_policy_explorer": True,
        "read_only": True
    }
    role_viewer = Role(name='Viewer', description='Read-Only Viewer', permissions=viewer_perms)
    db.session.add(role_viewer)
    
    db.session.commit()
    
    print("Creating Default Admin User...")
    admin_user = User(username='admin', email='admin@issec.local', full_name='System Administrator', position='IT Security')
    admin_user.set_password('admin123')
    db.session.add(admin_user)
    db.session.commit()
    
    # Assign Global Role
    assignment = UserCompanyRole(user_id=admin_user.id, company_id=None, role_id=role_admin.id)
    db.session.add(assignment)
    db.session.commit()
    
    print("Admin user created and assigned global Admin role.")
    print("Schema update complete.")
