from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_required, current_user
from app.models.user import User
from app.models.core import Role, UserCompanyRole, Company
from app.extensions.db import db
import uuid

user_role_bp = Blueprint('user_role', __name__)

@user_role_bp.route('/admin/users/<uuid:user_id>/roles')
@login_required
def manage_user_roles(user_id):
    if not current_user.has_permission('manage_users') and current_user.username != 'admin':
        flash("Acceso denegado", "danger")
        return redirect(url_for('main.index'))
        
    user = User.query.get(user_id)
    if not user:
        flash("Usuario no encontrado", "danger")
        return redirect(url_for('main.list_users'))
        
    roles = Role.query.all()
    companies = Company.query.all()
    
    # Organize assignments for display
    assignments = []
    for assign in user.company_roles:
        assignments.append({
            'row_id': assign.id, # Using the new Surrogate PK
            'role_name': assign.role.name,
            'scope': 'Global' if assign.company_id is None else assign.company.name,
            'is_global': assign.company_id is None,
        })
        
    return render_template('admin/user_roles.html', 
                           user=user, 
                           roles=roles, 
                           companies=companies, 
                           assignments=assignments)

@user_role_bp.route('/admin/users/<uuid:user_id>/roles/add', methods=['POST'])
@login_required
def add_user_role(user_id):
    if not current_user.has_permission('manage_users') and current_user.username != 'admin':
        flash("Acceso denegado", "danger")
        return redirect(url_for('main.index'))
        
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('main.list_users'))
        
    role_id = request.form.get('role_id')
    company_id_input = request.form.get('company_id')
    
    if not role_id:
        flash("Debe seleccionar un rol", "warning")
        return redirect(url_for('user_role.manage_user_roles', user_id=user.id))
        
    target_company_id = None
    if company_id_input and company_id_input != 'global':
        target_company_id = company_id_input
        
    # Check if assignment exists
    # If target_company_id is None (Global), filter logic handles it correctly
    exists = UserCompanyRole.query.filter_by(
        user_id=user.id, 
        role_id=role_id, 
        company_id=target_company_id
    ).first()
    
    if exists:
        flash("El usuario ya tiene este rol asignado en este contexto.", "warning")
    else:
        # Prevent multiple Global Roles? Optional. Assuming multiple allows union of permissions.
        # But for simplicity, checks if user already has A global role if implementing "One Global User Role" policy.
        # Here we allow multiple.
        
        assign = UserCompanyRole(user_id=user.id, role_id=role_id, company_id=target_company_id)
        db.session.add(assign)
        db.session.commit()
        flash("Rol asignado exitosamente.", "success")
        
    return redirect(url_for('user_role.manage_user_roles', user_id=user.id))

@user_role_bp.route('/admin/users/<uuid:user_id>/roles/delete/<uuid:assignment_id>', methods=['POST'])
@login_required
def delete_user_role(user_id, assignment_id):
    if not current_user.has_permission('manage_users') and current_user.username != 'admin':
        flash("Acceso denegado", "danger")
        return redirect(url_for('main.index'))
        
    assign = UserCompanyRole.query.get(assignment_id)
    if assign:
        # Prevent deleting the last Admin Global role of the 'admin' user is critical logic 
        # but admin user is usually safe.
        db.session.delete(assign)
        db.session.commit()
        flash("Asignación de rol eliminada.", "success")
        
    return redirect(url_for('user_role.manage_user_roles', user_id=user_id))
