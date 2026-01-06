"""
Policy API Endpoints
/api/v1/policies/*
"""
from flask import request, jsonify, g, abort
from flask_login import login_required
from app.api.v1 import api_v1_bp
from app.models.policy import Policy
from app.models.equipo import Equipo
from app.models.site import Site
from app.decorators import company_required, product_required
from app.extensions.db import db
from app.services.policy_diff_service import PolicyDiffService
from sqlalchemy import or_, func, desc, asc
import json
import uuid
import os


@api_v1_bp.route('/policies', methods=['GET'])
@login_required
@company_required
@product_required('policy_explorer')
def api_list_policies():
    """
    List policies with filters and pagination
    
    Query Parameters:
        page (int): Page number (default: 1)
        per_page (int): Items per page (default: 32, max: 512)
        device_id (uuid): Filter by device
        vdom (str): Filter by VDOM
        src_intf (str): Filter by source interface
        dst_intf (str): Filter by destination interface
        src_addr (str): Filter by source address
        dst_addr (str): Filter by destination address
        service (str): Filter by service
        action (str): Filter by action (ACCEPT/DENY)
        q (str): Search in policy_id and name
        zero_bytes (bool): Only policies with 0 bytes
        zero_hits (bool): Only policies with 0 hits
        show_dupes (bool): Only duplicate policies
        show_nat (bool): Only NAT enabled policies
        sort (str): Sort field (bytes, hits, id, service, action, vdom)
        order (str): Sort order (asc, desc)
    
    Returns:
        JSON with policies array, pagination info, and metadata
    """
    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 32, type=int)
    if per_page not in [8, 16, 32, 64, 128, 256, 512]:
        per_page = 32
    
    # Sorting
    sort_by = request.args.get('sort', 'bytes')
    order = request.args.get('order', 'desc')

    # Filters
    f_device = request.args.get('device_id')
    if f_device:
        try:
            uuid.UUID(f_device)
        except ValueError:
            # Invalid UUID, ignore filter or return error?
            # Return empty list or 400. Let's return 400 to be clear.
            return jsonify({'success': False, 'error': f'Invalid device_id: {f_device}'}), 400

    f_src_intf = request.args.get('src_intf')
    f_dst_intf = request.args.get('dst_intf')
    f_src_addr = request.args.get('src_addr')
    f_dst_addr = request.args.get('dst_addr')
    f_service = request.args.get('service')
    f_action = request.args.get('action')
    f_search = request.args.get('q')
    f_vdom = request.args.get('vdom')
    f_policy_id = request.args.get('policy_id')
    
    # Boolean filters
    f_zero_bytes = request.args.get('zero_bytes') == 'true'
    f_zero_hits = request.args.get('zero_hits') == 'true'
    f_show_dupes = request.args.get('show_dupes') == 'true'
    f_ignore_nat = request.args.get('ignore_nat') == 'true'
    f_show_nat = request.args.get('show_nat') == 'true'

    # Build query
    query = g.tenant_session.query(Policy).join(Equipo).join(Site)

    if f_device:
        query = query.filter(Policy.device_id == f_device)
    if f_vdom:
        query = query.filter(Policy.vdom == f_vdom)
    if f_policy_id:
        query = query.filter(Policy.policy_id == f_policy_id)
    if f_src_intf:
        query = query.filter(Policy.src_intf.ilike(f"%{f_src_intf}%"))
    if f_dst_intf:
        query = query.filter(Policy.dst_intf.ilike(f"%{f_dst_intf}%"))
    if f_src_addr:
        query = query.filter(Policy.src_addr.ilike(f"%{f_src_addr}%"))
    if f_dst_addr:
        query = query.filter(Policy.dst_addr.ilike(f"%{f_dst_addr}%"))
    if f_service:
        query = query.filter(Policy.service.ilike(f"%{f_service}%"))
    if f_action:
        query = query.filter(Policy.action == f_action)
    
    if f_show_nat:
        query = query.filter(Policy.nat == 'Enabled')

    if f_search:
        query = query.filter(or_(
            Policy.policy_id.ilike(f"%{f_search}%"),
            Policy.name.ilike(f"%{f_search}%")
        ))

    if f_zero_bytes:
        query = query.filter(Policy.bytes_int == 0)
    if f_zero_hits:
        query = query.filter(Policy.hit_count == 0)

    # Duplicates logic
    if f_show_dupes:
        json_dest = func.coalesce(
            Policy.raw_data['Destination'].astext,
            Policy.dst_addr
        ).label('dest_display')
        
        group_cols = [
            Policy.device_id,
            Policy.vdom,
            Policy.src_intf, Policy.dst_intf,
            Policy.src_addr, json_dest,
            Policy.service, Policy.action
        ]
        if not f_ignore_nat:
            group_cols.append(Policy.nat)

        subquery = g.tenant_session.query(*group_cols)\
            .group_by(*group_cols)\
            .having(func.count(Policy.uuid) > 1)\
            .subquery()

        json_dest_compare = func.coalesce(
            Policy.raw_data['Destination'].astext,
            Policy.dst_addr
        )

        conditions = [
            Policy.device_id == subquery.c.device_id,
            Policy.vdom == subquery.c.vdom,
            Policy.src_intf == subquery.c.src_intf,
            Policy.dst_intf == subquery.c.dst_intf,
            Policy.src_addr == subquery.c.src_addr,
            json_dest_compare == subquery.c.dest_display,
            Policy.service == subquery.c.service,
            Policy.action == subquery.c.action
        ]
        if not f_ignore_nat:
            conditions.append(Policy.nat == subquery.c.nat)

        query = query.join(subquery, db.and_(*conditions))
        query = query.order_by(Policy.device_id, Policy.vdom, Policy.service, Policy.src_addr)
    else:
        # Sorting
        sort_column = None
        if sort_by == 'id':
            sort_column = Policy.policy_id
        elif sort_by == 'service':
            sort_column = Policy.service
        elif sort_by == 'action':
            sort_column = Policy.action
        elif sort_by == 'bytes':
            sort_column = Policy.bytes_int
        elif sort_by == 'hits':
            sort_column = Policy.hit_count
        elif sort_by == 'src_intf':
            sort_column = Policy.src_intf
        elif sort_by == 'dst_intf':
            sort_column = Policy.dst_intf
        elif sort_by == 'vdom':
            sort_column = Policy.vdom
        
        if sort_column is not None:
            query = query.order_by(sort_column.asc() if order == 'asc' else sort_column.desc())

    # Execute query with pagination
    try:
        total = query.count()
        items = query.offset((page - 1) * per_page).limit(per_page).all()
        
        # Serialize policies
        policies_data = []
        for p in items:
            policies_data.append(serialize_policy(p))

        return jsonify({
            'success': True,
            'data': policies_data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            },
            'filters_applied': {
                'device_id': f_device,
                'vdom': f_vdom,
                'search': f_search,
                'zero_bytes': f_zero_bytes,
                'zero_hits': f_zero_hits,
                'show_dupes': f_show_dupes
            }
        })
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': f"Internal Error: {str(e)}",
            'traceback': traceback.format_exc()
        }), 500


@api_v1_bp.route('/policies/<uuid:policy_uuid>', methods=['GET'])
@login_required
@company_required
@product_required('policy_explorer')
def api_get_policy(policy_uuid):
    """
    Get a single policy by UUID
    
    Returns:
        JSON with full policy details including raw_data
    """
    policy = g.tenant_session.get(Policy, policy_uuid)
    if not policy:
        return jsonify({'success': False, 'error': 'Policy not found'}), 404
    
    data = serialize_policy(policy)
    data['raw_data'] = policy.raw_data
    
    return jsonify({
        'success': True,
        'data': data
    })


@api_v1_bp.route('/policies/import', methods=['POST'])
@login_required
@company_required
@product_required('policy_explorer')
def api_import_policies():
    """
    Import policies from JSON file - returns diff preview
    
    Request Body (multipart/form-data):
        device_id (uuid): Target device
        vdom (str): Target VDOM (default: 'root')
        json_file (file): JSON file with policies
    
    Returns:
        JSON with diff report and cache_key for confirmation
    """
    device_id = request.form.get('device_id')
    vdom = request.form.get('vdom', 'root')
    file = request.files.get('json_file')
    
    if not file or not device_id:
        return jsonify({
            'success': False,
            'error': 'device_id and json_file are required'
        }), 400
    
    try:
        content = json.load(file)
        data_list = content if isinstance(content, list) else [content]
        
        # Auto-detect VDOM from file
        if data_list and isinstance(data_list[0], dict):
            file_vdom = data_list[0].get('vdom')
            if file_vdom:
                vdom = file_vdom
        
        # Compare using DiffService
        diff_report = PolicyDiffService.compare_policies(g.tenant_session, device_id, vdom, data_list)
        
        # Store in cache for confirmation
        cache_key = str(uuid.uuid4())
        cache_data = {
            'device_id': device_id,
            'vdom': vdom,
            'diff': diff_report,
            'raw_data': data_list
        }
        
        cache_dir = os.path.join(os.getcwd(), 'tmp_cache')
        os.makedirs(cache_dir, exist_ok=True)
        
        with open(os.path.join(cache_dir, f"{cache_key}.json"), 'w') as f:
            json.dump(cache_data, f)
        
        return jsonify({
            'success': True,
            'cache_key': cache_key,
            'target_vdom': vdom,
            'diff': diff_report
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@api_v1_bp.route('/policies/import/confirm', methods=['POST'])
@login_required
@company_required
@product_required('policy_explorer')
def api_confirm_import():
    """
    Confirm and apply a pending policy import
    
    Request Body (JSON):
        cache_key (str): Key from import preview
    
    Returns:
        JSON with counts of added, modified, deleted policies
    """
    data = request.get_json()
    cache_key = data.get('cache_key') if data else None
    
    if not cache_key:
        return jsonify({
            'success': False,
            'error': 'cache_key is required'
        }), 400
    
    cache_path = os.path.join(os.getcwd(), 'tmp_cache', f"{cache_key}.json")
    if not os.path.exists(cache_path):
        return jsonify({
            'success': False,
            'error': 'Import session expired or not found'
        }), 404
    
    try:
        with open(cache_path, 'r') as f:
            cache_data = json.load(f)
        
        device_id_str = cache_data['device_id']
        device_id = uuid.UUID(device_id_str)
        vdom = cache_data['vdom']
        diff = cache_data['diff']
        
        import_session_id = uuid.uuid4()
        
        from app.models.history import PolicyHistory
        from app.services.fortigate_importer import parse_bytes_str, get_nat_status, list_to_str, parse_hit_count
        
        count_add = 0
        count_mod = 0
        count_del = 0
        
        # Handle Deletes
        for item in diff['deleted']:
            pid = item['policy_id']
            pol = g.tenant_session.query(Policy).filter_by(device_id=device_id, vdom=vdom, policy_id=pid).first()
            if pol:
                history = PolicyHistory(
                    policy_uuid=pol.uuid,
                    device_id=device_id,
                    vdom=vdom,
                    import_session_id=import_session_id,
                    change_type='delete',
                    delta={'action': 'deleted', 'reason': 'Not present in new import'},
                    snapshot=pol.raw_data
                )
                g.tenant_session.add(history)
                g.tenant_session.delete(pol)
                count_del += 1
        
        # Handle Adds & Modified
        for r in cache_data['raw_data']:
            src_list = r.get('From') or r.get('srcintf') or []
            dst_list = r.get('To') or r.get('dstintf') or []
            
            pid = str(r.get('ID', '0'))
            pol = g.tenant_session.query(Policy).filter_by(device_id=device_id, vdom=vdom, policy_id=pid).first()
            
            src_str = list_to_str(src_list)
            dst_str = list_to_str(dst_list)
            b_int = parse_bytes_str(r.get('Bytes', '0 B'))
            hits = parse_hit_count(r.get('Hit Count', 0))
            nat_status = get_nat_status(r)
            
            new_src_addr = list_to_str(r.get('Source Address', r.get('Source', [])))
            new_dst_addr = list_to_str(r.get('Destination Address', r.get('Destination', [])))
            new_service = list_to_str(r.get('Service', []))
            new_action = r.get('Action', 'DENY')
            new_name = str(r.get('Name', '') or r.get('Policy', ''))[:250]
            
            if pol:
                # Check for changes
                changes = []
                old_data = pol.raw_data.copy() if pol.raw_data else {}
                
                if pol.src_intf != src_str:
                    changes.append(f"Source Interface: '{pol.src_intf}' → '{src_str}'")
                if pol.dst_intf != dst_str:
                    changes.append(f"Destination Interface: '{pol.dst_intf}' → '{dst_str}'")
                if pol.src_addr != new_src_addr:
                    changes.append(f"Source Address: '{pol.src_addr}' → '{new_src_addr}'")
                if pol.dst_addr != new_dst_addr:
                    changes.append(f"Destination Address: '{pol.dst_addr}' → '{new_dst_addr}'")
                if pol.service != new_service:
                    changes.append(f"Service: '{pol.service}' → '{new_service}'")
                if pol.action != new_action:
                    changes.append(f"Action: '{pol.action}' → '{new_action}'")
                if pol.nat != nat_status:
                    changes.append(f"NAT: '{pol.nat}' → '{nat_status}'")
                if pol.name != new_name:
                    changes.append(f"Name: '{pol.name}' → '{new_name}'")
                
                if changes:
                    history = PolicyHistory(
                        policy_uuid=pol.uuid,
                        device_id=device_id,
                        vdom=vdom,
                        import_session_id=import_session_id,
                        change_type='modify',
                        delta={
                            'changes': changes,
                            'fields_changed': len(changes),
                            'old_snapshot': old_data
                        },
                        snapshot=r
                    )
                    g.tenant_session.add(history)
                    count_mod += 1
                
                # Update policy
                pol.src_intf = src_str
                pol.dst_intf = dst_str
                pol.src_addr = new_src_addr
                pol.dst_addr = new_dst_addr
                pol.service = new_service
                pol.action = new_action
                pol.nat = nat_status
                pol.name = new_name
                pol.bytes_int = b_int
                pol.hit_count = hits
                pol.raw_data = r
                
            else:
                # Create new policy
                new_pol = Policy(
                    device_id=device_id,
                    vdom=vdom,
                    policy_id=pid,
                    src_intf=src_str,
                    dst_intf=dst_str,
                    src_addr=new_src_addr,
                    dst_addr=new_dst_addr,
                    service=new_service,
                    action=new_action,
                    nat=nat_status,
                    name=new_name,
                    bytes_int=b_int,
                    hit_count=hits,
                    raw_data=r
                )
                g.tenant_session.add(new_pol)
                g.tenant_session.flush()
                
                history = PolicyHistory(
                    policy_uuid=new_pol.uuid,
                    device_id=device_id,
                    vdom=vdom,
                    import_session_id=import_session_id,
                    change_type='create',
                    delta={'action': 'created', 'source': 'import'},
                    snapshot=r
                )
                g.tenant_session.add(history)
                count_add += 1

        g.tenant_session.commit()
        
        # Cleanup
        os.remove(cache_path)
        
        return jsonify({
            'success': True,
            'counts': {
                'added': count_add,
                'modified': count_mod,
                'deleted': count_del
            },
            'message': f'Sincronización completada: +{count_add} Nuevas, ~{count_mod} Actualizadas, -{count_del} Eliminadas.'
        })
        
    except Exception as e:
        g.tenant_session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_v1_bp.route('/policies/script', methods=['POST'])
@login_required
@company_required
@product_required('policy_explorer')
def api_generate_script():
    """
    Generate FortiGate CLI script for selected policies
    
    Request Body (JSON):
        action_type (str): 'disable' or 'delete'
        policy_uuids (list): List of policy UUIDs
    
    Returns:
        JSON with script content
    """
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'JSON body required'}), 400
    
    action = data.get('action_type')
    selected_uuids = data.get('policy_uuids', [])
    
    if not selected_uuids:
        return jsonify({
            'success': False,
            'error': 'No policies selected'
        }), 400
    
    if action not in ['disable', 'delete']:
        return jsonify({
            'success': False,
            'error': 'action_type must be "disable" or "delete"'
        }), 400
    
    policies = g.tenant_session.query(Policy).filter(Policy.uuid.in_(selected_uuids)).order_by(Policy.vdom).all()
    
    lines = [f"# Script Generado por ISSEC - Acción: {action.upper()}", ""]
    current_vdom = None
    
    for p in policies:
        if p.vdom != current_vdom:
            if current_vdom:
                lines.append("end")
            lines.append(f"config vdom")
            lines.append(f"edit {p.vdom}")
            lines.append(f"config firewall policy")
            current_vdom = p.vdom
            
        comment = f"# {p.name} (ID: {p.policy_id})"
        if action == 'disable':
            lines.append(f"    edit {p.policy_id}  {comment}")
            lines.append(f"        set status disable")
            lines.append(f"    next")
        elif action == 'delete':
            lines.append(f"    delete {p.policy_id}  {comment}")
            
    if current_vdom:
        lines.append("end")  # policy
        lines.append("end")  # vdom
        
    content = "\n".join(lines)
    
    return jsonify({
        'success': True,
        'script': content,
        'filename': f"script_{action}.conf",
        'policy_count': len(policies)
    })


@api_v1_bp.route('/policies/vdoms', methods=['GET'])
@login_required
@company_required
@product_required('policy_explorer')
def api_list_vdoms():
    """
    Get list of distinct VDOMs from policies
    
    Query Parameters:
        device_id (uuid): Optional, filter by device
    
    Returns:
        JSON with list of VDOM names
    """
    device_id = request.args.get('device_id')
    
    query = g.tenant_session.query(Policy.vdom).distinct()
    
    if device_id:
        query = query.filter(Policy.device_id == device_id)
    
    vdoms = [r[0] for r in query.order_by(Policy.vdom).all() if r[0]]
    
    return jsonify({
        'success': True,
        'data': vdoms
    })


def serialize_policy(policy):
    """Helper to serialize a Policy object to dict"""
    return {
        'uuid': str(policy.uuid),
        'policy_id': policy.policy_id,
        'name': policy.name,
        'device_id': str(policy.device_id),
        'vdom': policy.vdom,
        'src_intf': policy.src_intf,
        'dst_intf': policy.dst_intf,
        'src_addr': policy.src_addr,
        'dst_addr': policy.dst_addr,
        'service': policy.service,
        'action': policy.action,
        'nat': policy.nat,
        'bytes_int': policy.bytes_int,
        'hit_count': policy.hit_count,
        'device_name': policy.equipo.nombre if policy.equipo else None,
        'site_name': policy.equipo.site.nombre if policy.equipo and policy.equipo.site else None
    }
