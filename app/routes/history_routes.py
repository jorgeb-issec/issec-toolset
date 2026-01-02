from flask import Blueprint, render_template, g, request, flash, redirect, url_for, abort
from flask_login import login_required
from app.models.history import PolicyHistory
from app.models.policy import Policy
from app.models.equipo import Equipo
from app.decorators import company_required, product_required
from sqlalchemy import desc, func
import uuid
import json

history_bp = Blueprint('history', __name__, url_prefix='/history')

@history_bp.route('/device/<uuid:device_id>')
@login_required
@company_required
@product_required('policy_explorer')
def device_history(device_id):
    """Shows full history for a device, grouped by import sessions"""
    device = g.tenant_session.query(Equipo).get(device_id)
    if not device:
        abort(404)
    
    # Filter by VDOM and change_type if specified
    vdom_filter = request.args.get('vdom')
    change_type_filter = request.args.get('change_type')  # create, modify, delete
    
    # Query History grouped by import session
    query = g.tenant_session.query(PolicyHistory)\
        .filter_by(device_id=device_id)
    
    if vdom_filter:
        query = query.filter_by(vdom=vdom_filter)
    
    if change_type_filter and change_type_filter in ('create', 'modify', 'delete'):
        query = query.filter_by(change_type=change_type_filter)
    
    # Get all history items
    all_history = query.order_by(desc(PolicyHistory.change_date)).limit(500).all()
    
    # Group by import session
    sessions = {}
    for item in all_history:
        session_id = str(item.import_session_id) if item.import_session_id else 'legacy'
        if session_id not in sessions:
            sessions[session_id] = {
                'id': session_id,
                'date': item.change_date,
                'vdom': item.vdom,
                'history_items': [],
                'stats': {'create': 0, 'modify': 0, 'delete': 0}
            }
        sessions[session_id]['history_items'].append(item)
        sessions[session_id]['stats'][item.change_type] += 1
    
    # Convert to sorted list
    session_list = sorted(sessions.values(), key=lambda x: x['date'], reverse=True)
    
    # Get distinct VDOMs for filter
    vdoms_query = g.tenant_session.query(PolicyHistory.vdom)\
        .filter_by(device_id=device_id)\
        .distinct()\
        .order_by(PolicyHistory.vdom)\
        .all()
    distinct_vdoms = [r[0] for r in vdoms_query if r[0]]
    
    return render_template('admin/devices/history.html', 
                           device=device, 
                           sessions=session_list,
                           distinct_vdoms=distinct_vdoms,
                           current_vdom=vdom_filter,
                           current_change_type=change_type_filter,
                           title=f"Historial de Cambios - {device.hostname}")

@history_bp.route('/policy/<uuid:policy_uuid>')
@login_required
@company_required
@product_required('policy_explorer')
def policy_history(policy_uuid):
    """Shows history for a specific policy"""
    # Try to find policy
    policy = g.tenant_session.query(Policy).get(policy_uuid)
    
    query = g.tenant_session.query(PolicyHistory)\
        .filter_by(policy_uuid=policy_uuid)\
        .order_by(desc(PolicyHistory.change_date))
    history_items = query.all()
    
    device = None
    if history_items:
        device_id = history_items[0].device_id
        device = g.tenant_session.query(Equipo).get(device_id)
    elif policy:
        device = policy.equipo
    
    # Group by session for this policy too
    sessions = {}
    for item in history_items:
        session_id = str(item.import_session_id) if item.import_session_id else 'legacy'
        if session_id not in sessions:
            sessions[session_id] = {
                'id': session_id,
                'date': item.change_date,
                'vdom': item.vdom,
                'history_items': [],
                'stats': {'create': 0, 'modify': 0, 'delete': 0}
            }
        sessions[session_id]['history_items'].append(item)
        sessions[session_id]['stats'][item.change_type] += 1
    
    session_list = sorted(sessions.values(), key=lambda x: x['date'], reverse=True)
        
    return render_template('admin/devices/history.html', 
                           device=device, 
                           policy=policy,
                           sessions=session_list,
                           distinct_vdoms=[],
                           current_vdom=None,
                           title=f"Historial de Política {policy.policy_id if policy else 'Deleted'}")


@history_bp.route('/device/<uuid:device_id>/config')
@login_required
@company_required
def config_history(device_id):
    """Shows configuration history for a device"""
    from app.models.config_history import ConfigHistory
    
    device = g.tenant_session.query(Equipo).get(device_id)
    if not device:
        abort(404)
    
    # Get all config history entries
    history_items = g.tenant_session.query(ConfigHistory)\
        .filter_by(device_id=device_id)\
        .order_by(desc(ConfigHistory.change_date))\
        .all()
    
    return render_template('admin/devices/config_history.html', 
                           device=device, 
                           history_items=history_items,
                           title=f"Historial de Configuración - {device.hostname}")


@history_bp.route('/config/<uuid:history_id>/export')
@login_required
@company_required
def export_config_history(history_id):
    """Export a historical config as a downloadable file"""
    from flask import Response
    from app.models.config_history import ConfigHistory
    
    history_item = g.tenant_session.query(ConfigHistory).get(history_id)
    if not history_item:
        abort(404)
    
    if not history_item.raw_config:
        flash("Esta versión no tiene configuración raw guardada", "warning")
        return redirect(request.referrer or url_for('device.list_devices'))
    
    # Get device info for filename
    device = g.tenant_session.query(Equipo).get(history_item.device_id)
    hostname = device.hostname if device else "device"
    date_str = history_item.change_date.strftime('%Y%m%d_%H%M%S')
    filename = f"{hostname}_{date_str}.config"
    
    return Response(
        history_item.raw_config,
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )
