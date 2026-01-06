from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_required, current_user
from app.models.core import Role
from app.extensions.db import db
import uuid

role_bp = Blueprint('role', __name__)

AVAILABLE_PERMISSIONS = [
    {"key": "global_admin", "label": "Administrador Global (Acceso Total)"},
    {"key": "manage_tenants", "label": "Gestionar Empresas (Crear/Eliminar)"},
    {"key": "manage_users", "label": "Gestionar Usuarios (Crear/Eliminar)"},
    {"key": "manage_roles", "label": "Gestionar Roles"},
    {"key": "access_policy_explorer", "label": "Acceso a Policy Explorer"},
    {"key": "access_log_analyzer", "label": "Acceso a Log Analyzer"},
    {"key": "read_only", "label": "Modo Solo Lectura"},
]

@role_bp.route('/admin/roles')
@login_required
def list_roles():
    if not current_user.has_permission('global_admin') and not current_user.has_permission('manage_roles'):
         # Fallback for hardcoded admin during transition
         if current_user.username != 'admin':
             flash("Acceso denegado.", "danger")
             return redirect(url_for('main.index'))

    roles = Role.query.all()
    return render_template('admin/roles.html', roles=roles, permissions=AVAILABLE_PERMISSIONS)

@role_bp.route('/admin/roles/add', methods=['POST'])
@login_required
def add_role():
    if not current_user.has_permission('manage_roles') and current_user.username != 'admin':
        flash("Acceso denegado.", "danger")
        return redirect(url_for('main.index'))
        
    name = request.form.get('name')
    description = request.form.get('description')
    
    if not name:
        flash("El nombre del rol es requerido.", "warning")
        return redirect(url_for('role.list_roles'))
        
    if Role.query.filter_by(name=name).first():
        flash("Ya existe un rol con ese nombre.", "warning")
        return redirect(url_for('role.list_roles'))
        
    # Collect permissions
    perms = {}
    for p in AVAILABLE_PERMISSIONS:
        if request.form.get(f"perm_{p['key']}"):
            perms[p['key']] = True
            
    new_role = Role(name=name, description=description, permissions=perms)
    db.session.add(new_role)
    db.session.commit()
    
    flash(f"Rol '{name}' creado exitosamente.", "success")
    return redirect(url_for('role.list_roles'))

@role_bp.route('/admin/roles/edit/<uuid:role_id>', methods=['POST'])
@login_required
def edit_role(role_id):
    if not current_user.has_permission('manage_roles') and current_user.username != 'admin':
        flash("Acceso denegado.", "danger")
        return redirect(url_for('main.index'))
        
    role = Role.query.get(role_id)
    if not role:
        flash("Rol no encontrado.", "danger")
        return redirect(url_for('role.list_roles'))
        
    role.description = request.form.get('description')
    
    # Update Permissions
    perms = {}
    for p in AVAILABLE_PERMISSIONS:
        if request.form.get(f"perm_{p['key']}"):
            perms[p['key']] = True
            
    role.permissions = perms
    db.session.commit()
    
    flash(f"Rol '{role.name}' actualizado.", "success")
    return redirect(url_for('role.list_roles'))

@role_bp.route('/admin/roles/delete/<uuid:role_id>', methods=['POST'])
@login_required
def delete_role(role_id):
    if not current_user.has_permission('manage_roles') and current_user.username != 'admin':
        flash("Acceso denegado.", "danger")
        return redirect(url_for('main.index'))
        
    role = Role.query.get(role_id)
    if role:
        if role.name == 'Admin':
             flash("No puedes eliminar el rol Admin predeterminado.", "danger")
        else:
            db.session.delete(role)
            db.session.commit()
            flash("Rol eliminado.", "success")
            
    return redirect(url_for('role.list_roles'))
