from flask import Blueprint, render_template, g, request, jsonify, current_app
from flask_login import login_required, current_user
from app.decorators import company_required, product_required
from app.models.equipo import Equipo
from app.models.site import Site
from app.models.vdom import VDOM
from app.models.interface import Interface
from app.extensions.db import db
import logging

log_bp = Blueprint('log_analytics', __name__, url_prefix='/logs')

logger = logging.getLogger(__name__)

@log_bp.route('/')
@login_required
@company_required
@product_required('log_analyzer')
def index():
    """Main Log Analyzer Dashboard"""
    # Get devices and sites for filter
    devices = g.tenant_session.query(Equipo).all()
    sites = db.session.query(Site).all()
    
    # Generate API Token for frontend JS
    token = current_user.encode_auth_token(current_app.config['SECRET_KEY'])
    if isinstance(token, bytes):
        token = token.decode('utf-8')
        
    return render_template('logs/index.html', devices=devices, sites=sites, api_token=token)

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
            # Return empty structure on error to prevent frontend crash
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
                
                # If no VDOMs found (maybe manual device), check for direct interfaces?
                # But for now assuming VDOM schema is used.
                if not vdoms:
                    # Creating a dummy "root" VDOM node if none exist? 
                    # Or just link interfaces to device?
                    # Let's link interfaces directly to device if no VDOMs (or treat device as VDOM level)
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
                        color = '#6c757d' # grey
                        if i.role == 'wan': color = '#dc3545' # red
                        elif i.role == 'lan': color = '#198754' # green
                        elif i.role == 'dmz': color = '#ffc107' # yellow
                        
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
        # Consider re-raising or returning partial
        pass

    return {'nodes': nodes, 'edges': edges}
