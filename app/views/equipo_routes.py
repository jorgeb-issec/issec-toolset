from flask import Blueprint, render_template, request, redirect, url_for, flash, g
from flask_login import login_required
from app.models.equipo import Equipo
from app.models.site import Site 
from app.extensions.db import db
from app.decorators import company_required

equipo_bp = Blueprint('equipo', __name__, url_prefix='/equipos')

@equipo_bp.route('/', methods=['GET'])
@login_required
@company_required
def list_equipos():
    equipos = g.tenant_session.query(Equipo).all()
    # Annotate sites manually (Main DB)
    from app.extensions.db import db
    from app.models.site import Site
    sites = db.session.query(Site).all()
    site_map = {s.id: s for s in sites}
    for e in equipos:
        e.site = site_map.get(e.site_id)
        
    return render_template('equipos/list.html', equipos=equipos)

@equipo_bp.route('/create', methods=['GET', 'POST'])
@login_required
@company_required
def create_equipo():
    # 1. Traemos los sitios del Tenant (Ahora Main DB)
    sites = db.session.query(Site).all()
    
    if request.method == 'POST':
        try:
            import uuid
            site_id_str = request.form.get('site_id')
            site_uuid = uuid.UUID(site_id_str) if site_id_str else None
            
            nuevo = Equipo(
                site_id=site_uuid,
                nombre=request.form.get('nombre'),
                serial=request.form.get('serial'),
                ha_habilitado=(request.form.get('ha_habilitado') == 'on'),
                segundo_serial=request.form.get('segundo_serial'),
                hostname=request.form.get('hostname')
            )
            g.tenant_session.add(nuevo)
            g.tenant_session.commit()
            flash('Equipo registrado correctamente', 'success')
            return redirect(url_for('equipo.list_equipos'))
        except Exception as e:
            g.tenant_session.rollback()
            flash(f'Error al crear equipo: {str(e)}', 'danger')
            
    return render_template('equipos/create.html', sites=sites)