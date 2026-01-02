from functools import wraps
from flask import session, redirect, url_for, flash, abort, g
from flask_login import current_user
from app.models.core import Company

def company_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Even for admin/global roles, we need a company_id in session
        # to ensure g.tenant_session is initialized for tenant-specific routes.
        if 'company_id' not in session:
            flash('Por favor seleccione una empresa para acceder a esta sección.', 'warning')
            return redirect(url_for('auth.select_company'))
            
        # Extra safety check to ensure the session actually loaded correctly
        if not hasattr(g, 'tenant_session') or g.tenant_session is None:
            from app.services.tenant_service import TenantService
            try:
                g.tenant_session = TenantService.get_session(session['company_id'])
            except Exception:
                flash('Error al acceder a los datos de la empresa. Por favor, intente de nuevo.', 'danger')
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
