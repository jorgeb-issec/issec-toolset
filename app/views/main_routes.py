from flask import Blueprint, redirect, url_for, render_template, session, request, flash, current_app
from flask_login import login_required, current_user
from app.decorators import company_required
from app.models.core import Company, Role
from app.models.user import User
from app.extensions.db import db
from app.services.tenant_service import TenantService
import uuid
import os
from werkzeug.utils import secure_filename

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
@login_required
def index():
    # Load context
    company_id = session.get('company_id')
    is_admin = (current_user.username == 'admin')
    has_global_role = bool(current_user.get_global_role())
    
    # If no company selected and user has global permissions, show Admin Dashboard
    if not company_id and (is_admin or has_global_role):
        all_companies = Company.query.all()
        return render_template('admin/admin_dashboard.html', 
                               all_companies=all_companies,
                               is_admin=True,
                               title="Panel de Control Global")

    # If no company selected and user is a normal user, redirect to company selection
    if not company_id:
        flash('Por favor seleccione una empresa para comenzar.', 'info')
        return redirect(url_for('auth.select_company'))

    # If company IS selected, show Company Dashboard
    company = Company.query.get(company_id)
    if not company:
        session.pop('company_id', None)
        flash('La empresa seleccionada ya no existe.', 'danger')
        return redirect(url_for('auth.select_company'))

    # Permission check for company dashboard
    role_name = session.get('role_name', '')
    can_edit = (role_name == 'Admin' or is_admin or has_global_role)
    
    # Ensure products is list
    if company.products is None:
        company.products = []
        
    return render_template('admin/company_dashboard.html', 
                           company=company,
                           can_edit=can_edit,
                           is_admin=(is_admin or has_global_role),
                           title=f"Dashboard - {company.name}")

@main_bp.route('/company/edit', methods=['POST'])
@login_required
def edit_company():
    # Verify permission
    # Verify permission
    role_name = session.get('role_name', '')
    # Allow 'Admin' (Company Admin), 'Global Admin' (Session), or 'admin' user, or explicit permission
    if role_name not in ['Admin', 'Global Admin'] and current_user.username != 'admin' and not current_user.has_permission('manage_company'):
        flash("No tienes permisos para editar la empresa", "danger")
        return redirect(url_for('main.index'))
    
    company_id = session.get('company_id')
    company = Company.query.get(company_id)
    
    if company:
        name = request.form.get('name')
        if name:
            company.name = name
            
        # Products
        products = request.form.getlist('products')
        company.products = products
        
        # Logo Upload
        if 'logo' in request.files:
            file = request.files['logo']
            if file and file.filename != '':
                filename = secure_filename(file.filename)
                # Use UUID to prevent collisions
                unique_filename = f"{uuid.uuid4()}_{filename}"
                upload_path = os.path.join(current_app.root_path, 'static', 'uploads', unique_filename)
                file.save(upload_path)
                company.logo = unique_filename
        
        # Gemini API Key (only for admin/global roles or company admin)
        gemini_api_key = request.form.get('gemini_api_key')
        if gemini_api_key is not None:
             company.gemini_api_key = gemini_api_key

        db.session.commit()
        
        session['company_name'] = company.name # Update Session
        flash("Datos de la empresa actualizados", "success")
        
    return redirect(url_for('main.index'))

@main_bp.route('/admin/settings')
@login_required
def admin_settings():
    # Allow admin user or anyone with global permissions
    is_admin = (current_user.username == 'admin')
    has_global_role = bool(current_user.get_global_role())
    
    if not (is_admin or has_global_role):
        flash("Acceso denegado a la configuración global.", "danger")
        return redirect(url_for('main.index'))
        
    all_companies = Company.query.all()
    all_users = User.query.all()
    all_roles = Role.query.all()
    
    return render_template('admin/settings.html',
                           all_companies=all_companies,
                           all_users=all_users,
                           all_roles=all_roles,
                           title="Configuración del Sistema")

# --- ADMIN ROUTES ---

@main_bp.route('/admin/company/add', methods=['POST'])
@login_required
@login_required
def add_company():
    # Allow admin user or anyone with 'manage_companies' permission globally
    if current_user.username != 'admin' and not current_user.has_permission('manage_companies'):
        flash("Acceso denegado", "danger")
        return redirect(url_for('main.index'))
        
    name = request.form.get('name')
    products = request.form.getlist('products')
    
    if not name:
        flash("Falta el nombre de la empresa", "warning")
        return redirect(url_for('main.index'))
        
    try:
        TenantService.create_tenant(name, products)
        flash(f"Empresa '{name}' y base de datos creadas exitosamente.", "success")
    except Exception as e:
        flash(f"Error creando empresa: {str(e)}", "danger")
        
    return redirect(url_for('main.index'))

@main_bp.route('/admin/company/delete/<uuid:company_id>', methods=['POST'])
@login_required
@login_required
def delete_company(company_id):
    if current_user.username != 'admin' and not current_user.has_permission('manage_companies'):
        flash("Acceso denegado", "danger")
        return redirect(url_for('main.index'))
        
    try:
        # Check if we are deleting the current one
        is_current = (str(company_id) == session.get('company_id'))
             
        TenantService.delete_tenant(company_id)
        
        if is_current:
            session.pop('company_id', None)
            session.pop('company_name', None)
            session.pop('role_name', None)
            flash("Empresa eliminada. Por favor selecciona otra empresa.", "info")
            return redirect(url_for('auth.select_company'))
            
        flash("Empresa eliminada correctamente.", "success")
    except Exception as e:
         flash(f"Error eliminando empresa: {str(e)}", "danger")
         
    return redirect(url_for('main.index'))

# --- USER MANAGEMENT ROUTES ---

@main_bp.route('/admin/users')
@login_required
@login_required
def list_users():
    if current_user.username != 'admin' and not current_user.has_permission('manage_users'):
        flash("Acceso denegado", "danger")
        return redirect(url_for('main.index'))
    
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@main_bp.route('/admin/users/add', methods=['POST'])
@login_required
@login_required
def add_user():
    if current_user.username != 'admin' and not current_user.has_permission('manage_users'):
        flash("Acceso denegado", "danger")
        return redirect(url_for('main.index'))
        
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')
    full_name = request.form.get('full_name')
    position = request.form.get('position')
    
    if not username or not password or not email:
        flash("Usuario, contraseña y email son requeridos", "warning")
        return redirect(url_for('main.list_users'))
        
    if User.query.filter((User.username == username) | (User.email == email)).first():
        flash("El usuario o email ya existe", "warning")
        return redirect(url_for('main.list_users'))

    profile_pic_filename = None
    if 'profile_pic' in request.files:
        file = request.files['profile_pic']
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4()}_{filename}"
            upload_path = os.path.join(current_app.root_path, 'static', 'uploads', unique_filename)
            file.save(upload_path)
            profile_pic_filename = unique_filename
        
    new_user = User(username=username, email=email, full_name=full_name, position=position, profile_pic=profile_pic_filename)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    
    flash(f"Usuario {username} creado correctamente.", "success")
    return redirect(url_for('main.list_users'))

@main_bp.route('/admin/users/reset_password/<uuid:user_id>', methods=['POST'])
@login_required
@login_required
def reset_user_password(user_id):
    if current_user.username != 'admin' and not current_user.has_permission('manage_users'):
         flash("Acceso denegado", "danger")
         return redirect(url_for('main.index'))
        
    user = User.query.get(user_id)
    new_password = request.form.get('new_password')
    
    if user and new_password:
        user.set_password(new_password)
        db.session.commit()
        flash(f"Contraseña para {user.username} actualizada.", "success")
    else:
        flash("Error actualizando contraseña.", "danger")
        
    return redirect(url_for('main.list_users'))

@main_bp.route('/admin/users/delete/<uuid:user_id>', methods=['POST'])
@login_required
@login_required
def delete_user(user_id):
    if current_user.username != 'admin' and not current_user.has_permission('manage_users'):
        flash("Acceso denegado", "danger")
        return redirect(url_for('main.index'))
        
    user = User.query.get(user_id)
    if user:
        if user.username == 'admin':
            flash("No puedes eliminar al usuario admin principal.", "danger")
        else:
            db.session.delete(user)
            db.session.commit()
            flash(f"Usuario {user.username} eliminado.", "success")
    
    return redirect(url_for('main.list_users'))