from functools import wraps
from flask import session, redirect, url_for, flash, abort
from flask_login import current_user
from app.models.core import Company

def company_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Allow admin user or users with global role
        if current_user.is_authenticated:
            if current_user.username == 'admin':
                return f(*args, **kwargs)
            if current_user.get_global_role():
                return f(*args, **kwargs)
        
        if 'company_id' not in session:
            flash('Por favor seleccione una empresa.', 'warning')
            return redirect(url_for('auth.select_company'))
        return f(*args, **kwargs)
    return decorated_function

def product_required(product_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Admin always has access
            if current_user.username == 'admin':
                return f(*args, **kwargs)
                
            company_id = session.get('company_id')
            if not company_id:
                return redirect(url_for('auth.select_company'))
                
            # We need to fetch the company to check products
            # Since this is likely used AFTER company_required, we could rely on that,
            # but for safety, let's query. To avoid overhead, we rely on session cache if feasible?
            # No, let's query safely.
            company = Company.query.get(company_id)
            if not company:
                flash("Empresa no encontrada.", "danger")
                return redirect(url_for('auth.select_company'))
                
            products = company.products or []
            if product_name not in products:
                flash(f"No tienes acceso a la herramienta: {product_name}", "danger")
                return redirect(url_for('main.index'))
                
            # Should also check USER role? 
            # Current req is "Company has tool". User permission is separate (User->Role->Permissions).
            # This decorator checks "Does the TENANT have the LICENSE".
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator
