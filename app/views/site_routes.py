from flask import Blueprint, render_template, request, redirect, url_for, flash, session, g
from flask_login import login_required, current_user
from app.models.site import Site
from app.models.equipo import Equipo
from app.extensions.db import db
from app.decorators import company_required
import uuid

site_bp = Blueprint('site', __name__)

@site_bp.route('/admin/sites')
@login_required
@company_required
def list_sites():
    # Sites are now Global/Main DB
    sites = db.session.query(Site).all()
    # If we need device counts, we must query tenant DB for each
    for s in sites:
         # Annotate on the fly (careful with N+1 queries, but sites are few)
         s.device_count = g.tenant_session.query(Equipo).filter(Equipo.site_id == s.id).count()

    return render_template('admin/sites/list.html', sites=sites)

@site_bp.route('/admin/sites/add', methods=['POST'])
@login_required
@company_required
def add_site():
    name = request.form.get('name')
    address = request.form.get('address')
    
    if not name:
        flash("El nombre del sitio es obligatorio", "warning")
        return redirect(url_for('site.list_sites'))
        
    # Check duplicate in Main DB
    if db.session.query(Site).filter_by(nombre=name).first():
        flash("Ya existe un sitio con ese nombre", "warning")
        return redirect(url_for('site.list_sites'))
        
    new_site = Site(nombre=name, direccion=address)
    db.session.add(new_site)
    db.session.commit()
    
    flash("Sitio creado correctamente", "success")
    return redirect(url_for('site.list_sites'))

@site_bp.route('/admin/sites/delete/<uuid:site_id>', methods=['GET'])
@login_required
@company_required
def confirm_delete_site(site_id):
    """Show confirmation page with migration options if site has equipos"""
    # Main DB
    site = db.session.query(Site).get(site_id)
    if not site:
        flash("Sitio no encontrado", "danger")
        return redirect(url_for('site.list_sites'))
    
    # Tenant DB: Check for attached equipment
    equipos = g.tenant_session.query(Equipo).filter(Equipo.site_id == site_id).all()
    
    # Get other sites for migration option (Main DB)
    other_sites = db.session.query(Site).filter(Site.id != site_id).all()
    
    return render_template('admin/sites/confirm_delete.html', 
                           site=site, 
                           equipos=equipos,
                           other_sites=other_sites)

@site_bp.route('/admin/sites/delete/<uuid:site_id>', methods=['POST'])
@login_required
@company_required
def delete_site(site_id):
    """Delete site, optionally migrating equipos first"""
    # Main DB
    site = db.session.query(Site).get(site_id)
    if not site:
        flash("Sitio no encontrado", "danger")
        return redirect(url_for('site.list_sites'))
    
    action = request.form.get('action')
    target_site_id = request.form.get('target_site_id')
    
    # Tenant DB: Check equipment
    equipos = g.tenant_session.query(Equipo).filter(Equipo.site_id == site_id).all()
    
    if equipos:
        if action == 'migrate' and target_site_id:
            # Migrate all equipos to target site
            # Validate target site exists in Main DB
            target_site = db.session.query(Site).get(uuid.UUID(target_site_id))
            if target_site:
                for equipo in equipos:
                    equipo.site_id = target_site.id
                g.tenant_session.commit()
                flash(f"Se migraron {len(equipos)} equipos a {target_site.nombre}", "info")
            else:
                flash("Sitio destino no encontrado", "danger")
                return redirect(url_for('site.confirm_delete_site', site_id=site_id))
        elif action == 'delete_all':
            # Delete all equipos (cascade will delete policies)
            for equipo in equipos:
                g.tenant_session.delete(equipo)
            g.tenant_session.commit()
            flash(f"Se eliminaron todos los equipos del sitio", "warning")
        else:
            flash("Debe elegir migrar o eliminar los equipos", "warning")
            return redirect(url_for('site.confirm_delete_site', site_id=site_id))
    
    # Now delete the site from Main DB
    db.session.delete(site)
    db.session.commit()
    flash(f"Sitio '{site.nombre}' eliminado correctamente", "success")
    
    return redirect(url_for('site.list_sites'))

@site_bp.route('/admin/sites/<uuid:site_id>/edit', methods=['POST'])
@login_required
@company_required
def edit_site(site_id):
    """Edit site name and address"""
    # Main DB
    site = db.session.query(Site).get(site_id)
    if not site:
        flash("Sitio no encontrado", "danger")
        return redirect(url_for('site.list_sites'))
    
    nombre = request.form.get('nombre')
    direccion = request.form.get('direccion')
    
    if not nombre:
        flash("El nombre es obligatorio", "warning")
        return redirect(url_for('site.list_sites'))
    
    # Check for duplicate name in Main DB
    existing = db.session.query(Site).filter(Site.nombre == nombre, Site.id != site_id).first()
    if existing:
        flash("Ya existe otro sitio con ese nombre", "warning")
        return redirect(url_for('site.list_sites'))
    
    site.nombre = nombre
    site.direccion = direccion
    db.session.commit()
    
    flash("Sitio actualizado correctamente", "success")
    return redirect(url_for('site.list_sites'))