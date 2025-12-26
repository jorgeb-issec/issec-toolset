from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app, g, jsonify
from flask_login import login_required, current_user
from app.models.equipo import Equipo
from app.models.site import Site
from app.models.vdom import VDOM
from app.extensions.db import db
from app.decorators import company_required
from app.services.config_parser import ConfigParserService
import uuid
import os
from werkzeug.utils import secure_filename

device_bp = Blueprint('device', __name__)

@device_bp.route('/admin/devices')
@login_required
@company_required
def list_devices():
    devices = g.tenant_session.query(Equipo).all()
    sites = g.tenant_session.query(Site).all()
    return render_template('admin/devices/list.html', devices=devices, sites=sites)

@device_bp.route('/admin/devices/add', methods=['POST'])
@login_required
@company_required
def add_device():
    name = request.form.get('name')
    serial = request.form.get('serial')
    site_id = request.form.get('site_id')
    hostname = request.form.get('hostname')
    
    if not name or not serial or not site_id:
        flash("Nombre, Serial y Sitio son obligatorios", "warning")
        return redirect(url_for('device.list_devices'))
        
    if g.tenant_session.query(Equipo).filter_by(serial=serial).first():
        flash("Ya existe un equipo con ese número de serie", "warning")
        return redirect(url_for('device.list_devices'))
        
    new_device = Equipo(
        nombre=name,
        serial=serial,
        site_id=uuid.UUID(site_id),
        hostname=hostname,
        ha_habilitado = (request.form.get('ha_habilitado') == 'on')
    )
    g.tenant_session.add(new_device)
    g.tenant_session.commit()
    
    flash("Equipo agregado correctamente", "success")
    return redirect(url_for('device.list_devices'))

@device_bp.route('/admin/devices/import', methods=['POST'])
@login_required
@company_required
def import_device_config():
    if 'config_file' not in request.files:
        flash("No se seleccionó ningún archivo", "warning")
        return redirect(url_for('device.list_devices'))
        
    file = request.files['config_file']
    if file.filename == '':
        flash("No se seleccionó ningún archivo", "warning")
        return redirect(url_for('device.list_devices'))
        
    if file:
        content = file.read().decode('utf-8', errors='ignore')
        
        try:
            # Parse Config
            data = ConfigParserService.parse_config(content)
            
            target_site_id = request.form.get('site_id')
            if not target_site_id:
                 flash("Debe seleccionar un sitio para importar el equipo.", "warning")
                 return redirect(url_for('device.list_devices'))
            
            # Handle Serial Number
            # Priority: 1) User input, 2) Parsed from config, 3) Generate temporary
            manual_serial = request.form.get('serial_number', '').strip()
            
            if manual_serial:
                # User provided serial manually
                data['serial'] = manual_serial
            elif not data['serial']:
                # Serial not found in config and not provided by user
                # Generate a temporary serial based on hostname
                temp_serial = f"TEMP-{data.get('hostname', 'UNKNOWN')}-{hash(content) % 100000}"
                data['serial'] = temp_serial
                flash(f"⚠️ Serial no encontrado en el archivo. Se generó un serial temporal: {temp_serial}. Por favor, actualícelo manualmente.", "warning")
            
            # Check exist in Tenant DB
            existing_device = g.tenant_session.query(Equipo).filter_by(serial=data['serial']).first()
            
            if existing_device:
                # Update existing device provided by user request
                existing_device.hostname = data.get('hostname')
                existing_device.config_data = data.get('config_data')
                existing_device.site_id = uuid.UUID(target_site_id)
                # We do not overwrite 'nombre' to preserve user custom alias if set, 
                # unless it matches the old serial/hostname? Let's keep it simple and just update tech specs.
                
                # Sync VDOMs for existing
                if data['config_data'].get('vdoms'):
                     existing_vdoms = g.tenant_session.query(VDOM).filter_by(device_id=existing_device.id).all()
                     existing_names = {v.name for v in existing_vdoms}
                     for v_name in data['config_data']['vdoms']:
                        if v_name not in existing_names:
                             new_vdom = VDOM(device_id=existing_device.id, name=v_name, comments="Imported from Global Config")
                             g.tenant_session.add(new_vdom)
                
                g.tenant_session.commit()
                flash(f"Equipo {existing_device.hostname} actualizado con la nueva configuración.", "info")
            else:
                new_device = Equipo(
                    nombre=data.get('hostname') or data.get('serial'), # Default name
                    hostname=data.get('hostname'),
                    serial=data['serial'],
                    site_id=uuid.UUID(target_site_id),
                    ha_habilitado=False,
                    config_data=data.get('config_data') # Save parsed detailed config
                )
                # Add device to session and flush to get ID
                g.tenant_session.add(new_device)
                g.tenant_session.flush()
                
                # Now create VDOMs if present in config
                if data['config_data'].get('vdoms'):
                    for v_name in data['config_data']['vdoms']:
                        new_vdom = VDOM(device_id=new_device.id, name=v_name, comments="Imported from Global Config")
                        g.tenant_session.add(new_vdom)
                
                g.tenant_session.commit()
                flash(f"Equipo {new_device.hostname} importado correctamente con detalles.", "success")
                
        except Exception as e:
            flash(f"Error importando configuración: {str(e)}", "danger")
            g.tenant_session.rollback()
            
    return redirect(url_for('device.list_devices'))

@device_bp.route('/admin/devices/view/<uuid:device_id>')
@login_required
@company_required
def view_device(device_id):
    device = g.tenant_session.query(Equipo).get(device_id)
    if not device:
         flash("Equipo no encontrado", "danger")
         return redirect(url_for('device.list_devices'))
    # Re-attach to session if needed for lazy loading
    # Or rely on template accessing relationships? 
    # Since session is open, relationships like device.site should load.
    
    vdoms = g.tenant_session.query(VDOM).filter_by(device_id=device.id).all()
    sites = g.tenant_session.query(Site).all()
    return render_template('admin/devices/view.html', device=device, vdoms=vdoms, sites=sites)

@device_bp.route('/admin/devices/delete/<uuid:device_id>', methods=['POST'])
@login_required
@company_required
def delete_device(device_id):
    device = g.tenant_session.query(Equipo).get(device_id)
    if device:
        g.tenant_session.delete(device)
        g.tenant_session.commit()
        flash("Equipo eliminado.", "success")
            
    return redirect(url_for('device.list_devices'))
@device_bp.route('/admin/devices/vdom/<uuid:device_id>/add', methods=['POST'])
@login_required
@company_required
def add_vdom(device_id):
    vdom_name = request.form.get('vdom_name')
    if not vdom_name:
        flash("El nombre del VDOM es obligatorio", "warning")
        return redirect(url_for('device.view_device', device_id=device_id))
    
    # Check duplicate
    exists = g.tenant_session.query(VDOM).filter_by(device_id=device_id, name=vdom_name).first()
    if exists:
         flash("El VDOM ya existe en este equipo", "warning")
         return redirect(url_for('device.view_device', device_id=device_id))
         
    new_vdom = VDOM(device_id=device_id, name=vdom_name, comments="Manual creation")
    g.tenant_session.add(new_vdom)
    g.tenant_session.commit()
    
    flash("VDOM agregado correctamente", "success")
    return redirect(url_for('device.view_device', device_id=device_id))

@device_bp.route('/admin/devices/vdom/<uuid:vdom_id>/import', methods=['POST'])
@login_required
@company_required
def import_vdom_config(vdom_id):
    if 'config_file' not in request.files:
        flash("No se seleccionó ningún archivo", "warning")
        return redirect(request.referrer)
    
    file = request.files['config_file']
    if file.filename == '':
        flash("No se seleccionó ningún archivo", "warning")
        return redirect(request.referrer)
        
    if file:
        content = file.read().decode('utf-8', errors='ignore')
        try:
            # Parse Config
            data = ConfigParserService.parse_config(content)
            
            # Update VDOM
            vdom = g.tenant_session.query(VDOM).get(vdom_id)
            if vdom:
                vdom.config_data = data.get('config_data')
                g.tenant_session.commit()
                flash(f"Configuración importada para VDOM {vdom.name}", "success")
            else:
                 flash("VDOM no encontrado", "danger")
                 
        except Exception as e:
            flash(f"Error importando configuración: {str(e)}", "danger")
            g.tenant_session.rollback()
            
    return redirect(request.referrer)
    return redirect(request.referrer)

@device_bp.route('/admin/devices/<uuid:device_id>/import-vdom', methods=['POST'])
@login_required
@company_required
def import_new_vdom(device_id):
    if 'config_file' not in request.files:
        flash("No se seleccionó ningún archivo", "warning")
        return redirect(url_for('device.view_device', device_id=device_id))
    
    file = request.files['config_file']
    if file.filename == '':
        flash("No se seleccionó ningún archivo", "warning")
        return redirect(url_for('device.view_device', device_id=device_id))
        
    if file:
        content = file.read().decode('utf-8', errors='ignore')
        try:
            # Parse Config
            data = ConfigParserService.parse_config(content)
            
            vdom_name = data.get('vdom_name')
            
            # Fallback: if header didn't have name, try to ask user via prompt? 
            # or usage of filename? 
            # For now, require header or user form input (if we had one).
            # But we are using a simple file upload. 
            # Let's check if form has a name input override.
            if not vdom_name:
                vdom_name = request.form.get('vdom_name_override')
            
            if not vdom_name:
                 # Try to guess from filename? "vdom routing.conf"
                 fname = file.filename.lower()
                 if 'vdom' in fname:
                     parts = fname.split('vdom')
                     if len(parts) > 1:
                         # heuristic
                         potential = parts[1].strip().split(' ', 1)[0].split('.', 1)[0]
                         if potential: vdom_name = potential
            
            if not vdom_name:
                flash("No se pudo detectar el nombre del VDOM en el archivo. Use 'Agregar Manual' primero.", "warning")
                return redirect(url_for('device.view_device', device_id=device_id))
                
            # Check/Create VDOM
            vdom = g.tenant_session.query(VDOM).filter_by(device_id=device_id, name=vdom_name).first()
            if not vdom:
                vdom = VDOM(device_id=device_id, name=vdom_name, comments=f"Imported from {file.filename}")
                g.tenant_session.add(vdom)
                # We need to commit to get ID if needed, or just let session handle it.
            
            vdom.config_data = data.get('config_data')
            g.tenant_session.commit()
            
            flash(f"VDOM '{vdom_name}' importado exitosamente.", "success")
                 
        except Exception as e:
            flash(f"Error importando VDOM: {str(e)}", "danger")
            g.tenant_session.rollback()
            
            
    return redirect(url_for('device.view_device', device_id=device_id))

@device_bp.route('/admin/devices/<uuid:device_id>/vdoms/json', methods=['GET'])
@login_required
@company_required
def get_device_vdoms_json(device_id):
    vdoms = g.tenant_session.query(VDOM).filter_by(device_id=device_id).order_by(VDOM.name).all()
    return jsonify([{'id': v.id, 'name': v.name} for v in vdoms])

@device_bp.route('/admin/devices/<uuid:device_id>/edit', methods=['POST'])
@login_required
@company_required
def edit_device(device_id):
    device = g.tenant_session.query(Equipo).get(device_id)
    if not device:
        flash("Equipo no encontrado", "danger")
        return redirect(url_for('device.list_devices'))

    nombre = request.form.get('nombre')
    serial = request.form.get('serial')
    hostname = request.form.get('hostname')
    site_id = request.form.get('site_id')
    
    if not nombre or not serial:
        flash("El nombre y el serial son obligatorios", "warning")
        return redirect(url_for('device.view_device', device_id=device_id))
        
    # Check serial conflict if changed
    if serial != device.serial:
        exists = g.tenant_session.query(Equipo).filter_by(serial=serial).first()
        if exists:
            flash(f"El serial {serial} ya está en uso por otro equipo.", "warning")
            return redirect(url_for('device.view_device', device_id=device_id))
            
    device.nombre = nombre
    device.serial = serial
    device.hostname = hostname
    if site_id:
        device.site_id = uuid.UUID(site_id)
    
    device.ha_habilitado = (request.form.get('ha_habilitado') == 'on')
    
    g.tenant_session.commit()
    flash("Equipo actualizado correctamente", "success")
    return redirect(url_for('device.view_device', device_id=device_id))

@device_bp.route('/admin/devices/vdom/<uuid:vdom_id>/edit', methods=['POST'])
@login_required
@company_required
def edit_vdom(vdom_id):
    vdom = g.tenant_session.query(VDOM).get(vdom_id)
    if not vdom:
        flash("VDOM no encontrado", "danger")
        return redirect(request.referrer)
        
    name = request.form.get('name')
    comments = request.form.get('comments')
    
    if not name:
        flash("El nombre del VDOM es obligatorio", "warning")
        return redirect(request.referrer)
        
    # Check duplicate name in same device if changed
    if name != vdom.name:
        exists = g.tenant_session.query(VDOM).filter_by(device_id=vdom.device_id, name=name).first()
        if exists:
            flash(f"El VDOM '{name}' ya existe en este equipo.", "warning")
            return redirect(request.referrer)
            
    vdom.name = name
    vdom.comments = comments
    g.tenant_session.commit()
    
    flash("VDOM actualizado correctamente", "success")
    return redirect(request.referrer)

@device_bp.route('/admin/devices/<uuid:device_id>/refresh', methods=['POST'])
@login_required
@company_required
def refresh_device_config(device_id):
    """Actualizar la configuración de un equipo existente con un nuevo archivo .config"""
    device = g.tenant_session.query(Equipo).get(device_id)
    if not device:
        flash("Equipo no encontrado", "danger")
        return redirect(url_for('device.list_devices'))
    
    if 'config_file' not in request.files:
        flash("No se seleccionó ningún archivo", "warning")
        return redirect(url_for('device.view_device', device_id=device_id))
    
    file = request.files['config_file']
    if file.filename == '':
        flash("No se seleccionó ningún archivo", "warning")
        return redirect(url_for('device.view_device', device_id=device_id))
    
    if file:
        content = file.read().decode('utf-8', errors='ignore')
        try:
            # Parse Config
            data = ConfigParserService.parse_config(content)
            
            # Update device config_data
            device.config_data = data.get('config_data')
            device.hostname = data.get('hostname') or device.hostname
            
            # Update HA status from parsed config
            ha_info = data.get('config_data', {}).get('ha', {})
            device.ha_habilitado = ha_info.get('enabled', False)
            
            # Sync VDOMs
            if data['config_data'].get('vdoms'):
                existing_vdoms = g.tenant_session.query(VDOM).filter_by(device_id=device.id).all()
                existing_names = {v.name for v in existing_vdoms}
                for v_name in data['config_data']['vdoms']:
                    if v_name not in existing_names:
                        new_vdom = VDOM(device_id=device.id, name=v_name, comments="Imported from Global Config")
                        g.tenant_session.add(new_vdom)
            
            g.tenant_session.commit()
            
            ha_mode = ha_info.get('mode', 'standalone')
            ha_msg = f" | HA: {ha_mode.upper()}" if ha_info.get('enabled') else ""
            flash(f"Configuración de '{device.hostname}' actualizada correctamente.{ha_msg}", "success")
            
        except Exception as e:
            flash(f"Error actualizando configuración: {str(e)}", "danger")
            g.tenant_session.rollback()
    
    return redirect(url_for('device.view_device', device_id=device_id))

