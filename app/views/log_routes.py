from flask import Blueprint, render_template, g, request, jsonify, current_app
from flask_login import login_required, current_user
from app.decorators import company_required, product_required
from app.models.equipo import Equipo
from app.models.site import Site
from app.models.vdom import VDOM
from app.models.interface import Interface
from app.models.log_entry import LogEntry
from app.models.security_recommendation import SecurityRecommendation
from app.extensions.db import db
from sqlalchemy import func, desc, or_
import logging
from datetime import datetime, timedelta

log_bp = Blueprint('log_analytics', __name__, url_prefix='/analyzer')

logger = logging.getLogger(__name__)

@log_bp.route('/')
@login_required
@company_required
@product_required('log_analyzer')
def index():
    """Main Log Analyzer Dashboard & List API"""
    
    # If it's a JSON request (heuristic: page param or explicit header)
    if request.args.get('page') or request.headers.get('Accept') == 'application/json':
        return get_logs_list()

    # Get devices and sites for filter
    devices = g.tenant_session.query(Equipo).all()
    sites = db.session.query(Site).all()
    
    # Generate API Token for frontend JS
    token = current_user.encode_auth_token(current_app.config['SECRET_KEY'])
    if isinstance(token, bytes):
        token = token.decode('utf-8')
        
    return render_template('logs/index.html', devices=devices, sites=sites, api_token=token)

def get_logs_list():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 32, type=int)
        search = request.args.get('q', '').lower()
        device_id = request.args.get('device_id')
        
        query = g.tenant_session.query(LogEntry)
        
        # Filters
        if device_id and device_id != 'None':
            query = query.filter(LogEntry.device_id == device_id)
            
        if search:
            query = query.filter(or_(
                LogEntry.src_ip.ilike(f"%{search}%"),
                LogEntry.dst_ip.ilike(f"%{search}%"),
                LogEntry.service.ilike(f"%{search}%"),
                LogEntry.policy_id.cast(db.String).ilike(f"%{search}%")
            ))
            
        # Sort
        query = query.order_by(desc(LogEntry.timestamp))
        
        # Paginate
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        data = []
        for log in pagination.items:
            data.append({
                'id': str(log.id),
                'timestamp': log.timestamp.isoformat() if log.timestamp else None,
                'level': log.level,
                'vdom': log.vdom or (log.vdom_ref.name if log.vdom_ref else '-'),
                'log_type': log.log_type,
                'src_ip': log.src_ip,
                'dst_ip': log.dst_ip,
                'service': log.service,
                'action': log.action,
                'app': log.app,
                'raw_data': log.raw_data
            })
            
        return jsonify({
            'data': data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': pagination.total,
                'pages': pagination.pages
            }
        })
        
    except Exception as e:
        logger.error(f"Error listing logs: {e}")
        return jsonify({'data': [], 'error': str(e)}), 500

@log_bp.route('/<uuid:log_id>', methods=['GET'])
@login_required
@company_required
def get_log_details(log_id):
    try:
        log = g.tenant_session.query(LogEntry).get(log_id)
        if not log:
            return jsonify({'success': False, 'error': 'Log not found'}), 404
            
        return jsonify({
            'success': True,
            'data': {
                'id': str(log.id),
                'timestamp': log.timestamp.isoformat(),
                'raw_data': log.raw_data
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@log_bp.route('/stats', methods=['GET'])
@login_required
@company_required
def get_stats():
    """Dashboard Stats"""
    try:
        device_id = request.args.get('device_id')
        
        q_total = g.tenant_session.query(func.count(LogEntry.id))
        q_threats = g.tenant_session.query(func.count(LogEntry.id)).filter(LogEntry.action == 'deny')
        
        if device_id:
            q_total = q_total.filter(LogEntry.device_id == device_id)
            q_threats = q_threats.filter(LogEntry.device_id == device_id)
            
        total = q_total.scalar() or 0
        threats = q_threats.scalar() or 0
        
        # Recommendations
        rec_count = g.tenant_session.query(func.count(SecurityRecommendation.id)).filter(SecurityRecommendation.status == 'open').scalar() or 0
        
        return jsonify({
            'totalResults': total, # Naming to match typical Chart.js or frontend
            'total_logs': total,
            'threats': threats,
            'recommendations': rec_count,
            'volume': '0 GB' # Placeholder or calc
        })
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return jsonify({'error': str(e)}), 500

@log_bp.route('/recommendations', methods=['GET'])
@login_required
@company_required
def get_recommendations():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 5, type=int)
        
        query = g.tenant_session.query(SecurityRecommendation).filter(SecurityRecommendation.status == 'open')
        query = query.order_by(desc(SecurityRecommendation.created_at))
        
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        data = []
        for rec in pagination.items:
            data.append({
                'id': str(rec.id),
                'title': rec.title,
                'description': rec.description,
                'recommendation': rec.recommendation,
                'cli_remediation': rec.cli_remediation, # v1.3.1
                'severity': rec.severity,
                'created_at': rec.created_at.isoformat()
            })
            
        return jsonify({
            'data': data,
            'pagination': {
                'total': pagination.total,
                'pages': pagination.pages
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Topology Routes (Restored)
@log_bp.route('/topology', methods=['GET', 'POST'])
@login_required
@company_required
def topology():
    """Get or Update Topology Data"""
    if request.method == 'POST':
        data = request.get_json()
        site_id = data.get('site_id')
        topology_json = data.get('topology') 
        
        if not site_id:
             return jsonify({'error': 'Site ID required'}), 400
             
        try:
            site = db.session.query(Site).get(site_id)
            if not site:
                return jsonify({'error': 'Site not found'}), 404
            
            site.topology_data = topology_json
            db.session.commit()
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"Error saving topology: {e}")
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    else: # GET
        site_id = request.args.get('site_id')
        force_refresh = request.args.get('refresh') == 'true'
        mode = request.args.get('mode')
        
        try:
            # If site_id provided, check if it has saved data
            if site_id and site_id != 'all' and not force_refresh:
                site = db.session.query(Site).get(site_id)
                if site and site.topology_data:
                    # Return saved data if exists
                    return jsonify(site.topology_data)
            
            # Otherwise generate fresh
            return jsonify(generate_topology_data(site_id))
        except Exception as e:
            logger.error(f"Error generating topology: {e}")
            return jsonify({'nodes': [], 'edges': [], 'error': str(e)})

@log_bp.route('/analyze/topology', methods=['POST'])
@login_required
@company_required
def analyze_topology_route():
    """Trigger AI analysis of topology"""
    data = request.get_json()
    site_id = data.get('site_id')
    
    # Force regeneration to find new inefficiencies
    topo_data = generate_topology_data(site_id)
    
    # Save it back to site if site_id matches
    if site_id:
        try:
            site = db.session.query(Site).get(site_id)
            if site:
                site.topology_data = topo_data
                db.session.commit()
        except Exception as e:
            logger.error(f"Error saving analyzed topology: {e}")
            
    return jsonify({'success': True, 'message': 'Analysis complete', 'data': topo_data})


def generate_topology_data(site_id=None):
    nodes = []
    edges = []
    
    try:
        # 1. Sites
        query = db.session.query(Site)
        if site_id and site_id != 'all':
            query = query.filter(Site.id == site_id)
        sites = query.all()
        
        for s in sites:
            site_node_id = str(s.id)
            nodes.append({
                'id': site_node_id, 
                'label': s.nombre, 
                'group': 'site', 
                'level': 0,
                'color': '#0d6efd' 
            })
            
            # 2. Devices (Tenant DB)
            devs = g.tenant_session.query(Equipo).filter(Equipo.site_id == s.id).all()
            
            for d in devs:
                dev_id = str(d.id)
                nodes.append({
                    'id': dev_id,
                    'label': d.hostname or d.name,
                    'group': 'device',
                    'level': 1
                })
                edges.append({'from': site_node_id, 'to': dev_id})
                
                # 3. VDOMs
                vdoms = g.tenant_session.query(VDOM).filter(VDOM.device_id == d.id).all()
                
                if not vdoms:
                    pass

                for v in vdoms:
                    vdom_id = str(v.id)
                    nodes.append({
                        'id': vdom_id,
                        'label': v.name,
                        'group': 'vdom',
                        'level': 2
                    })
                    edges.append({'from': dev_id, 'to': vdom_id})
                    
                    # 4. Interfaces
                    intfs = g.tenant_session.query(Interface).filter(Interface.vdom_id == v.id).all()
                    for i in intfs:
                        intf_id = str(i.id)
                        color = '#6c757d'
                        if i.role == 'wan': color = '#dc3545'
                        elif i.role == 'lan': color = '#198754'
                        elif i.role == 'dmz': color = '#ffc107'
                        
                        label = f"{i.name}"
                        if i.ip_address:
                            label += f"\n{i.ip_address}"
                        
                        nodes.append({
                            'id': intf_id,
                            'label': label,
                            'group': 'interface',
                            'level': 3,
                            'color': color
                        })
                        edges.append({'from': vdom_id, 'to': intf_id})
                        
    except Exception as e:
        logger.error(f"Error in generate_topology_data: {e}")
        pass

    return {'nodes': nodes, 'edges': edges}
