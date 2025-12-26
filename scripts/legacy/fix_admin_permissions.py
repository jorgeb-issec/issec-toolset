from app import create_app
from app.extensions.db import db
from app.models.core import Role

app = create_app()

with app.app_context():
    admin_role = Role.query.filter_by(name='Admin').first()
    if admin_role:
        print(f"Current Admin Permissions: {admin_role.permissions}")
        
        perms = admin_role.permissions or {}
        updated = False
        
        if not perms.get('manage_users'):
            perms['manage_users'] = True
            updated = True
            
        if not perms.get('manage_companies'):
            perms['manage_companies'] = True
            updated = True
        
        # Check specific 'manage_company' (singular) used in edit? 
        # I used 'manage_company' in edit_company route refactor.
        if not perms.get('manage_company'):
            perms['manage_company'] = True
            updated = True
            
        if updated:
            # Re-assign to trigger detection of change if it's a dict
            admin_role.permissions = dict(perms) 
            db.session.commit()
            print(f"Updated Admin Permissions: {admin_role.permissions}")
        else:
            print("Permissions already correct.")
    else:
        print("Role 'Admin' not found!")
