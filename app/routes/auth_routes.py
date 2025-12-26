from flask import Blueprint, render_template, redirect, url_for, request, flash, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from app.models.user import User
from app.models.core import Company, UserCompanyRole
from app.extensions.db import db
from werkzeug.utils import secure_filename
import os
import uuid

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            # return redirect(url_for('main.index'))
            return redirect(url_for('auth.select_company'))
        else:
            flash('Usuario o contraseña inválidos', 'danger')
            
    return render_template('login.html')

    return render_template('login.html')

@auth_bp.route('/enter_global_admin')
@login_required
def enter_global_admin():
    # Verify Global Access
    is_global = False
    if current_user.username == 'admin':
        is_global = True
    else:
        # Check if user has a role with company_id IS NULL
        if current_user.company_roles.filter(UserCompanyRole.company_id.is_(None)).first():
            is_global = True
            
    if not is_global:
        flash("No tienes permisos globales.", "danger")
        return redirect(url_for('auth.select_company'))
        
    # Clear company context
    session.pop('company_id', None)
    session.pop('company_name', None)
    session['role_name'] = 'Global Admin' # Temporary Role Name for display
    
    flash("Ingresando como Administrador Global", "info")
    return redirect(url_for('main.index'))

@auth_bp.route('/select_company')
@login_required
def select_company():
    companies = []
    global_access = False
    
    if current_user.username == 'admin':
        # Admin ve todas las empresas. 
        all_comps = Company.query.all()
        class AdminAssignment:
            def __init__(self, c):
                self.company = c
                self.role = type('obj', (object,), {'name': 'Global Admin'})
        companies = [AdminAssignment(c) for c in all_comps]
        global_access = True
    else:
        # Fetch standard company assignments
        companies = current_user.company_roles.filter(UserCompanyRole.company_id.isnot(None)).all()
        
        # Check for Global Roles (company_id IS NULL)
        global_roles = current_user.company_roles.filter(UserCompanyRole.company_id.is_(None)).all()
        if global_roles:
            global_access = True
        
    return render_template('select_company.html', companies=companies, global_access=global_access)

@auth_bp.route('/set_company/<company_id>')
@login_required
def set_company(company_id):
    target_company = None
    role_name = None
    
    if current_user.username == 'admin':
        target_company = Company.query.get(company_id)
        role_name = 'Admin'
        if not target_company:
             flash('Empresa no encontrada.', 'danger')
             return redirect(url_for('auth.select_company'))
    else:
        # Verificar que el usuario tenga acceso a esta empresa
        assignment = current_user.company_roles.filter_by(company_id=company_id).first()
        
        if not assignment:
            flash('No tienes acceso a esta empresa.', 'danger')
            return redirect(url_for('auth.select_company'))
        
        target_company = assignment.company
        role_name = assignment.role.name
    
    # Guardar en sesión
    session['company_id'] = str(target_company.id)
    session['company_name'] = target_company.name
    session['role_name'] = role_name
    
    flash(f'Empresa seleccionada: {target_company.name}', 'success')
    return redirect(url_for('main.index'))

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':

        # 1. Update Basic Info
        email = request.form.get('email')
        full_name = request.form.get('full_name')
        position = request.form.get('position')
        
        if email:
            # Check uniqueness if changed
            existing = User.query.filter_by(email=email).first()
            if existing and existing.id != current_user.id:
                flash("El email ya está en uso por otro usuario.", "warning")
            else:
                current_user.email = email
                
        current_user.full_name = full_name
        current_user.position = position
        
        # 2. Profile Picture Upload
        created_pic = False
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and file.filename != '':
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4()}_{filename}"
                upload_path = os.path.join(current_app.root_path, 'static', 'uploads', unique_filename)
                file.save(upload_path)
                
                current_user.profile_pic = unique_filename
                created_pic = True

        # 3. Change Password (Optional)
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        pass_msg = None
        
        if new_password:
            if not current_password:
                 flash("Para cambiar la contraseña debes ingresar la contraseña actual.", "warning")
            elif not current_user.check_password(current_password):
                flash('La contraseña actual es incorrecta.', 'danger')
            elif new_password != confirm_password:
                flash('Las nuevas contraseñas no coinciden.', 'warning')
            else:
                current_user.set_password(new_password)
                pass_msg = "Contraseña actualizada."

        db.session.commit()
        
        msg_parts = []
        if created_pic: msg_parts.append("Foto actualizada")
        if pass_msg: msg_parts.append(pass_msg)
        if not created_pic and not pass_msg: msg_parts.append("Datos actualizados")
        
        flash(f"Perfil guardado: {', '.join(msg_parts)}", 'success')
            
    return render_template('profile.html')