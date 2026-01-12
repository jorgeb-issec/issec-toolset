"""
Devices API Endpoints
/api/v1/devices/*
"""
from flask import request, jsonify, g, session, current_app
from flask_login import login_required
from app.api.v1 import api_v1_bp
from app.models.equipo import Equipo
from app.models.vdom import VDOM
from app.decorators import company_required
from app.extensions.db import db
from app.services.config_parser import ConfigParserService
import uuid
import os


@api_v1_bp.route('/devices', methods=['GET'])
@login_required
@company_required
def api_list_devices():
    """
    List all devices for current company
    
    Query Parameters:
        site_id (uuid): Filter by site
        with_vdoms (bool): Include VDOM list in response
    
    Returns:
        JSON with devices array
    """
    site_id = request.args.get('site_id')
    with_vdoms = request.args.get('with_vdoms') == 'true'
    
    query = g.tenant_session.query(Equipo)
    
    if site_id:
        query = query.filter(Equipo.site_id == site_id)
    
    devices = query.all()
    
    # v1.3.1 - Refactor Site Name resolution
    # Prefetch site names from Main DB
    from app.models.site import Site
    site_names = {}
    if devices:
        distinct_site_ids = list(set([d.site_id for d in devices if d.site_id]))
        if distinct_site_ids:
            sites = db.session.query(Site).filter(Site.id.in_(distinct_site_ids)).all()
            site_names = {s.id: s.nombre for s in sites}
    
    data = []
    for d in devices:
        # Pass site map to serializer or resolve here
        device_data = serialize_device(d)
        if d.site_id in site_names:
            device_data['site_name'] = site_names[d.site_id]
            
        if with_vdoms:
            vdoms = g.tenant_session.query(VDOM).filter_by(device_id=d.id).all()
            device_data['vdoms'] = [{'id': str(v.id), 'name': v.name} for v in vdoms]
        data.append(device_data)
    
    return jsonify({
        'success': True,
        'data': data,
        'count': len(data)
    })


@api_v1_bp.route('/devices/<uuid:device_id>', methods=['GET'])
@login_required
@company_required
def api_get_device(device_id):
    """
    Get a single device by UUID
    
    Returns:
        JSON with full device details including config_data and VDOMs
    """
    device = g.tenant_session.query(Equipo).get(device_id)
    if not device:
        return jsonify({'success': False, 'error': 'Device not found'}), 404
    
    data = serialize_device(device)
    
    # Enrich site name individually
    from app.models.site import Site
    if device.site_id:
        site = db.session.query(Site).filter(Site.id == device.site_id).first()
        if site:
            data['site_name'] = site.nombre
            
    data['config_data'] = device.config_data
    
    # Include VDOMs
    vdoms = g.tenant_session.query(VDOM).filter_by(device_id=device.id).all()
    data['vdoms'] = [serialize_vdom(v) for v in vdoms]
    
    return jsonify({
        'success': True,
        'data': data
    })


@api_v1_bp.route('/devices/<uuid:device_id>/vdoms', methods=['GET'])
@login_required
@company_required
def api_get_device_vdoms(device_id):
    """
    Get VDOMs for a specific device
    
    Returns:
        JSON with VDOMs array
    """
    vdoms = g.tenant_session.query(VDOM).filter_by(device_id=device_id).order_by(VDOM.name).all()
    
    return jsonify({
        'success': True,
        'data': [serialize_vdom(v) for v in vdoms]
    })


@api_v1_bp.route('/devices', methods=['POST'])
@login_required
@company_required
def api_create_device():
    """
    Create a new device
    
    Request Body (JSON):
        name (str): Device name
        serial (str): Serial number
        site_id (uuid): Site ID
        hostname (str): Optional hostname
        ha_enabled (bool): HA status
    
    Returns:
        JSON with created device
    """
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'JSON body required'}), 400
    
    name = data.get('name')
    serial = data.get('serial')
    site_id = data.get('site_id')
    
    if not name or not serial or not site_id:
        return jsonify({
            'success': False,
            'error': 'name, serial, and site_id are required'
        }), 400
    
    # Check duplicate serial
    if g.tenant_session.query(Equipo).filter_by(serial=serial).first():
        return jsonify({
            'success': False,
            'error': 'A device with this serial number already exists'
        }), 409
    
    new_device = Equipo(
        nombre=name,
        serial=serial,
        site_id=uuid.UUID(site_id),
        hostname=data.get('hostname'),
        ha_habilitado=data.get('ha_enabled', False)
    )
    g.tenant_session.add(new_device)
    g.tenant_session.commit()
    
    return jsonify({
        'success': True,
        'data': serialize_device(new_device),
        'message': 'Device created successfully'
    }), 201


@api_v1_bp.route('/devices/<uuid:device_id>', methods=['PUT'])
@login_required
@company_required
def api_update_device(device_id):
    """
    Update a device
    
    Request Body (JSON):
        name (str): Device name
        serial (str): Serial number
        hostname (str): Hostname
        site_id (uuid): Site ID
        ha_enabled (bool): HA status
    
    Returns:
        JSON with updated device
    """
    device = g.tenant_session.query(Equipo).get(device_id)
    if not device:
        return jsonify({'success': False, 'error': 'Device not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'JSON body required'}), 400
    
    # Check serial conflict if changed
    new_serial = data.get('serial')
    if new_serial and new_serial != device.serial:
        exists = g.tenant_session.query(Equipo).filter_by(serial=new_serial).first()
        if exists:
            return jsonify({
                'success': False,
                'error': f'Serial {new_serial} is already in use'
            }), 409
        device.serial = new_serial
    
    if 'name' in data:
        device.nombre = data['name']
    if 'hostname' in data:
        device.hostname = data['hostname']
    if 'site_id' in data:
        device.site_id = uuid.UUID(data['site_id'])
    if 'ha_enabled' in data:
        device.ha_habilitado = data['ha_enabled']
    
    g.tenant_session.commit()
    
    return jsonify({
        'success': True,
        'data': serialize_device(device),
        'message': 'Device updated successfully'
    })


@api_v1_bp.route('/devices/<uuid:device_id>', methods=['DELETE'])
@login_required
@company_required
def api_delete_device(device_id):
    """
    Delete a device
    
    Returns:
        JSON with success message
    """
    device = g.tenant_session.query(Equipo).get(device_id)
    if not device:
        return jsonify({'success': False, 'error': 'Device not found'}), 404
    
    device_name = device.nombre
    g.tenant_session.delete(device)
    g.tenant_session.commit()
    
    return jsonify({
        'success': True,
        'message': f'Device {device_name} deleted successfully'
    })


@api_v1_bp.route('/devices/<uuid:device_id>/import-config', methods=['POST'])
@login_required
@company_required
def api_import_device_config(device_id):
    """
    Import/update device configuration from file
    
    Request Body (multipart/form-data):
        config_file (file): FortiGate config file
    
    Returns:
        JSON with import result and config delta
    """
    device = g.tenant_session.query(Equipo).get(device_id)
    if not device:
        return jsonify({'success': False, 'error': 'Device not found'}), 404
    
    if 'config_file' not in request.files:
        return jsonify({
            'success': False,
            'error': 'config_file is required'
        }), 400
    
    file = request.files['config_file']
    if file.filename == '':
        return jsonify({
            'success': False,
            'error': 'No file selected'
        }), 400
    
    try:
        content = file.read().decode('utf-8', errors='ignore')
        new_data = ConfigParserService.parse_config(content)
        new_config = new_data.get('config_data', {})
        
        # Calculate delta
        current_config = device.config_data or {}
        delta = calculate_config_delta(current_config, new_config)
        
        # Apply configuration
        device.config_data = new_config
        device.raw_config = content
        if new_data.get('hostname'):
            device.hostname = new_data['hostname']
        
        # Update HA status
        ha_info = new_config.get('ha', {})
        device.ha_habilitado = ha_info.get('enabled', False)
        
        # Sync VDOMs
        if new_config.get('vdoms'):
            existing_vdoms = g.tenant_session.query(VDOM).filter_by(device_id=device.id).all()
            existing_names = {v.name for v in existing_vdoms}
            new_vdoms_added = []
            for v_name in new_config['vdoms']:
                if v_name not in existing_names:
                    new_vdom = VDOM(device_id=device.id, name=v_name, comments="Imported from Config")
                    g.tenant_session.add(new_vdom)
                    new_vdoms_added.append(v_name)
        
        g.tenant_session.commit()
        
        return jsonify({
            'success': True,
            'delta': delta,
            'hostname': device.hostname,
            'ha_enabled': device.ha_habilitado,
            'message': f'Configuration imported for {device.hostname}'
        })
        
    except Exception as e:
        g.tenant_session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_v1_bp.route('/devices/<uuid:device_id>/vdoms', methods=['POST'])
@login_required
@company_required
def api_create_vdom(device_id):
    """
    Create a new VDOM for a device
    
    Request Body (JSON):
        name (str): VDOM name
        comments (str): Optional comments
    
    Returns:
        JSON with created VDOM
    """
    data = request.get_json()
    if not data or not data.get('name'):
        return jsonify({
            'success': False,
            'error': 'name is required'
        }), 400
    
    vdom_name = data['name']
    
    # Check duplicate
    exists = g.tenant_session.query(VDOM).filter_by(device_id=device_id, name=vdom_name).first()
    if exists:
        return jsonify({
            'success': False,
            'error': f'VDOM {vdom_name} already exists on this device'
        }), 409
    
    new_vdom = VDOM(
        device_id=device_id,
        name=vdom_name,
        comments=data.get('comments', 'Manual creation')
    )
    g.tenant_session.add(new_vdom)
    g.tenant_session.commit()
    
    return jsonify({
        'success': True,
        'data': serialize_vdom(new_vdom),
        'message': f'VDOM {vdom_name} created successfully'
    }), 201


# --- Sites API ---

@api_v1_bp.route('/sites', methods=['GET'])
@login_required
@company_required
def api_list_sites():
    """
    List all sites for current company
    
    Returns:
        JSON with sites array
    """

    # Fetch from Main DB
    from app.models.site import Site
    sites = db.session.query(Site).all()
    
    data = []
    for s in sites:
        site_data = {
            'id': str(s.id),
            'nombre': s.nombre
        }
        # Count devices per site (Tenant DB)
        # Equipment has site_id as plain UUID column now
        device_count = g.tenant_session.query(Equipo).filter(Equipo.site_id == s.id).count()
        site_data['device_count'] = device_count
        data.append(site_data)
    
    return jsonify({
        'success': True,
        'data': data
    })


# --- Helper Functions ---

def serialize_device(device):
    """Helper to serialize a Device (Equipo) object to dict"""
    return {
        'id': str(device.id),
        'nombre': device.nombre,
        'hostname': device.hostname,
        'serial': device.serial,
        'site_id': str(device.site_id) if device.site_id else None,
        'site_name': None, # Populated by caller via Main DB lookup
        'ha_enabled': device.ha_habilitado,
        'has_config': device.config_data is not None
    }


def serialize_vdom(vdom):
    """Helper to serialize a VDOM object to dict"""
    return {
        'id': str(vdom.id),
        'name': vdom.name,
        'comments': vdom.comments,
        'device_id': str(vdom.device_id)
    }


def calculate_config_delta(old_config, new_config):
    """Calculate differences between two config versions"""
    delta = {
        'interfaces': {'added': [], 'removed': [], 'modified': []},
        'vdoms': {'added': [], 'removed': []},
        'ha_changed': False,
        'ha_old': None,
        'ha_new': None,
    }
    
    # Compare interfaces
    old_intfs = {i['name']: i for i in old_config.get('interfaces', [])}
    new_intfs = {i['name']: i for i in new_config.get('interfaces', [])}
    
    old_names = set(old_intfs.keys())
    new_names = set(new_intfs.keys())
    
    delta['interfaces']['added'] = list(new_names - old_names)
    delta['interfaces']['removed'] = list(old_names - new_names)
    
    for name in old_names & new_names:
        if old_intfs[name] != new_intfs[name]:
            delta['interfaces']['modified'].append(name)
    
    # Compare VDOMs
    old_vdoms = set(old_config.get('vdoms', []))
    new_vdoms = set(new_config.get('vdoms', []))
    delta['vdoms']['added'] = list(new_vdoms - old_vdoms)
    delta['vdoms']['removed'] = list(old_vdoms - new_vdoms)
    
    # Compare HA
    old_ha = old_config.get('ha', {})
    new_ha = new_config.get('ha', {})
    if old_ha != new_ha:
        delta['ha_changed'] = True
        delta['ha_old'] = old_ha
        delta['ha_new'] = new_ha
    
    return delta
