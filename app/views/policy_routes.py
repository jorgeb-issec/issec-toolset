from flask import Blueprint, render_template, request, redirect, url_for, flash, Response, jsonify, g, abort, session
from flask_login import login_required
from app.models.policy import Policy
from app.models.equipo import Equipo
from app.models.site import Site
from app.services.fortigate_importer import process_policy_json
from app.services.policy_diff_service import PolicyDiffService
from app.extensions.db import db
from sqlalchemy import or_, func, desc, asc
from app.decorators import company_required, product_required
from app.utils.pagination import SimplePagination
import json
import uuid
import os

policy_bp = Blueprint('policy', __name__, url_prefix='/policies')

@policy_bp.before_request
@login_required
@company_required
@product_required('policy_explorer')
def before_request():
    pass # This applies to all routes in this BP? No, before_request doesn't work like a decorator on the view.
    # It runs before the view. If we return a response (redirect), it stops.
    pass
    
# Actually, using @before_request is cleaner than decorating every route if the WHOLE blueprint is for that product.
# Let's remove the decorators from individual routes and use before_request check?
# Or just decorate each one. Explicit is better.
# Let's use individual decorators to be standard.


# ... (Ruta /import se mantiene igual) ...
@policy_bp.route('/import', methods=['GET', 'POST'])
@login_required
@company_required
@product_required('policy_explorer')
def import_policies():
    equipos = g.tenant_session.query(Equipo).all()
    if request.method == 'POST':
        device_id = request.form.get('device_id')
        vdom = request.form.get('vdom', 'root')
        file = request.files.get('json_file')
        
        if file and device_id:
            try:
                # 1. Parse JSON
                content = json.load(file)
                data_list = content if isinstance(content, list) else [content]
                
                # AUTO-DETECT VDOM
                # If the JSON contains 'vdom' key in the first item, we use it.
                if data_list and isinstance(data_list[0], dict):
                    file_vdom = data_list[0].get('vdom')
                    if file_vdom:
                        if file_vdom != vdom:
                             flash(f"Detectado VDOM '{file_vdom}' en el archivo. Actualizando destino de importación.", 'info')
                        vdom = file_vdom
                
                # 2. Compare using DiffService
                diff_report = PolicyDiffService.compare_policies(g.tenant_session, device_id, vdom, data_list)
                
                # 3. Store in Session / Cache for 'Confirmation'
                # For simplicity, we'll serialize to a temp file and store path in session
                # In prod, use Redis or DB
                cache_key = str(uuid.uuid4())
                cache_data = {
                    'device_id': device_id,
                    'vdom': vdom,
                    'diff': diff_report,
                    'raw_data': data_list # Store the NEW data to be applied
                }
                
                # Ensure cache dir exists
                cache_dir = os.path.join(os.getcwd(), 'tmp_cache')
                os.makedirs(cache_dir, exist_ok=True)
                
                with open(os.path.join(cache_dir, f"{cache_key}.json"), 'w') as f:
                    json.dump(cache_data, f)
                
                # Render Diff View (Pass VDOM for UI)
                return render_template('policies/diff.html', diff=diff_report, cache_key=cache_key, target_vdom=vdom)
                
            except Exception as e:
                flash(f"Error procesando archivo: {str(e)}", 'danger')
        else:
            flash("Faltan datos obligatorios", "warning")
            
    return render_template('policies/import.html', equipos=equipos)

@policy_bp.route('/confirm_import', methods=['POST'])
@login_required
@company_required
@product_required('policy_explorer')
def confirm_import():
    cache_key = request.form.get('cache_key')
    if not cache_key:
        flash("Error de sesión: No se encontró la clave de caché", 'danger')
        return redirect(url_for('policy.import_policies'))
        
    cache_path = os.path.join(os.getcwd(), 'tmp_cache', f"{cache_key}.json")
    if not os.path.exists(cache_path):
        flash("La sesión de importación ha expirado", 'danger')
        return redirect(url_for('policy.import_policies'))
    
    try:
        with open(cache_path, 'r') as f:
            cache_data = json.load(f)
            
        # Re-Apply logic using the stored Data
        device_id_str = cache_data['device_id']
        device_id = uuid.UUID(device_id_str)
        vdom = cache_data['vdom']
        diff = cache_data['diff']
        
        # Generate import session ID to group all changes from this import
        import_session_id = uuid.uuid4()
        
        from app.models.history import PolicyHistory
        from app.services.fortigate_importer import parse_bytes_str, get_nat_status, list_to_str, parse_hit_count
        
        count_add = 0
        count_mod = 0
        count_del = 0
        
        # 1. Handle Deletes
        for item in diff['deleted']:
            pid = item['policy_id']
            pol = g.tenant_session.query(Policy).filter_by(device_id=device_id, vdom=vdom, policy_id=pid).first()
            if pol:
                # Save history before deleting
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
        
        # 2. Handle Adds & Modified (Upsert)
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
            
            if pol:
                # Capture changes for delta
                changes = []
                old_data = pol.raw_data.copy() if pol.raw_data else {}
                
                # Compare fields and build delta
                if pol.src_intf != src_str:
                    changes.append(f"Source Interface: '{pol.src_intf}' → '{src_str}'")
                if pol.dst_intf != dst_str:
                    changes.append(f"Destination Interface: '{pol.dst_intf}' → '{dst_str}'")
                
                new_src_addr = list_to_str(r.get('Source Address', r.get('Source', [])))
                if pol.src_addr != new_src_addr:
                    changes.append(f"Source Address: '{pol.src_addr}' → '{new_src_addr}'")
                
                new_dst_addr = list_to_str(r.get('Destination Address', r.get('Destination', [])))
                if pol.dst_addr != new_dst_addr:
                    changes.append(f"Destination Address: '{pol.dst_addr}' → '{new_dst_addr}'")
                
                new_service = list_to_str(r.get('Service', []))
                if pol.service != new_service:
                    changes.append(f"Service: '{pol.service}' → '{new_service}'")
                
                new_action = r.get('Action', 'DENY')
                if pol.action != new_action:
                    changes.append(f"Action: '{pol.action}' → '{new_action}'")
                
                if pol.nat != nat_status:
                    changes.append(f"NAT: '{pol.nat}' → '{nat_status}'")
                
                new_name = str(r.get('Name', '') or r.get('Policy', ''))[:250]
                if pol.name != new_name:
                    changes.append(f"Name: '{pol.name}' → '{new_name}'")
                
                if pol.bytes_int != b_int:
                    changes.append(f"Bytes: {pol.bytes_int} → {b_int}")
                
                if pol.hit_count != hits:
                    changes.append(f"Hit Count: {pol.hit_count} → {hits}")
                
                # Only save history if there are actual changes
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
                    src_addr=list_to_str(r.get('Source Address', r.get('Source', []))),
                    dst_addr=list_to_str(r.get('Destination Address', r.get('Destination', []))),
                    service=list_to_str(r.get('Service', [])),
                    action=r.get('Action', 'DENY'),
                    nat=nat_status,
                    name=str(r.get('Name', '') or r.get('Policy', ''))[:250],
                    bytes_int=b_int,
                    hit_count=hits,
                    raw_data=r 
                )
                g.tenant_session.add(new_pol)
                g.tenant_session.flush() # Flush to get UUID
                
                # Log History: CREATE
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
        
        flash(f"Sincronización completada: +{count_add} Nuevas, ~{count_mod} Actualizadas, -{count_del} Eliminadas.", 'success')
        return redirect(url_for('policy.list_policies'))
        
    except Exception as e:
        g.tenant_session.rollback()
        flash(f"Error aplicando cambios: {str(e)}", 'danger')
        return redirect(url_for('policy.import_policies'))

@policy_bp.route('/', methods=['GET'])
@login_required
@company_required
@product_required('policy_explorer')
def list_policies():
    # --- 1. PAGINACIÓN Y ORDEN ---
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 32, type=int)
    if per_page not in [8, 16, 32, 64, 128, 256, 512]: per_page = 32
    
    sort_by = request.args.get('sort', 'bytes')
    order = request.args.get('order', 'desc')

    # --- 2. FILTROS ---
    f_device = request.args.get('device_id')
    f_src_intf = request.args.get('src_intf')
    f_dst_intf = request.args.get('dst_intf')
    f_src_addr = request.args.get('src_addr')
    f_dst_addr = request.args.get('dst_addr')
    f_service = request.args.get('service')
    f_action = request.args.get('action')
    f_search = request.args.get('q')
    f_vdom = request.args.get('vdom')
    
    # Filtros Booleanos (Sliders)
    f_zero_bytes = request.args.get('zero_bytes') == 'on'
    f_zero_hits = request.args.get('zero_hits') == 'on'
    f_show_dupes = request.args.get('show_dupes') == 'on'
    f_ignore_nat = request.args.get('ignore_nat') == 'on'
    
    # CAMBIO: NAT ahora es booleano (Switch)
    f_show_nat = request.args.get('show_nat') == 'on'

    # --- 3. QUERY ---
    query = g.tenant_session.query(Policy).join(Equipo).join(Site)

    if f_device: query = query.filter(Policy.device_id == f_device)
    if f_vdom: query = query.filter(Policy.vdom == f_vdom)
    if f_src_intf: query = query.filter(Policy.src_intf.ilike(f"%{f_src_intf}%"))
    if f_dst_intf: query = query.filter(Policy.dst_intf.ilike(f"%{f_dst_intf}%"))
    if f_src_addr: query = query.filter(Policy.src_addr.ilike(f"%{f_src_addr}%"))
    if f_dst_addr: query = query.filter(Policy.dst_addr.ilike(f"%{f_dst_addr}%"))
    if f_service: query = query.filter(Policy.service.ilike(f"%{f_service}%"))
    if f_action: query = query.filter(Policy.action == f_action)
    
    # Nuevo Filtro NAT (Solo muestra si está habilitado)
    if f_show_nat:
        query = query.filter(Policy.nat == 'Enabled')

    if f_search:
        query = query.filter(or_(
            Policy.policy_id.ilike(f"%{f_search}%"),
            Policy.name.ilike(f"%{f_search}%")
        ))

    if f_zero_bytes: query = query.filter(Policy.bytes_int == 0)
    if f_zero_hits: query = query.filter(Policy.hit_count == 0)

    # Lógica de Duplicados - Busca políticas con misma config en el MISMO VDOM
    if f_show_dupes:
        # Para duplicados, usamos el valor de Destination del JSON si existe
        # Esto asegura que el filtro coincida con lo que se muestra en la UI
        from sqlalchemy.sql.expression import label as sql_label
        
        # Expresión para obtener Destination del JSON, con fallback a dst_addr
        json_dest = func.coalesce(
            Policy.raw_data['Destination'].astext,
            Policy.dst_addr
        ).label('dest_display')
        
        # Columnas para agrupar (CON VDOM - queremos encontrar duplicados DENTRO del mismo vdom)
        group_cols = [
            Policy.device_id,
            Policy.vdom,
            Policy.src_intf, Policy.dst_intf,
            Policy.src_addr, json_dest,
            Policy.service, Policy.action
        ]
        if not f_ignore_nat: group_cols.append(Policy.nat)

        # Subquery: Buscar grupos con MÁS DE UNA política (duplicados en mismo VDOM)
        subquery = g.tenant_session.query(*group_cols)\
            .group_by(*group_cols)\
            .having(func.count(Policy.uuid) > 1)\
            .subquery()

        # Expresión para comparar (debe ser la misma que usamos en group_cols)
        json_dest_compare = func.coalesce(
            Policy.raw_data['Destination'].astext,
            Policy.dst_addr
        )

        # Condiciones de join (CON VDOM)
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
        if not f_ignore_nat: conditions.append(Policy.nat == subquery.c.nat)

        query = query.join(subquery, db.and_(*conditions))
        query = query.order_by(Policy.device_id, Policy.vdom, Policy.service, Policy.src_addr)


    # Ordenamiento
    if not f_show_dupes:
        sort_column = None
        if sort_by == 'id': sort_column = Policy.policy_id 
        elif sort_by == 'service': sort_column = Policy.service
        elif sort_by == 'action': sort_column = Policy.action
        elif sort_by == 'bytes': sort_column = Policy.bytes_int
        elif sort_by == 'hits': sort_column = Policy.hit_count
        elif sort_by == 'src_intf': sort_column = Policy.src_intf
        elif sort_by == 'dst_intf': sort_column = Policy.dst_intf
        elif sort_by == 'vdom': sort_column = Policy.vdom 
        
        if sort_column is not None:
            query = query.order_by(sort_column.asc() if order == 'asc' else sort_column.desc())

    # pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    pagination = SimplePagination(items, page, per_page, total)
    
    # Generar group_key para duplicados (para agrupación visual)
    # IMPORTANTE: Usar los mismos valores que se muestran en la UI (del raw_data cuando aplique)
    duplicate_groups = {}
    if f_show_dupes and items:
        for p in items:
            # Extraer valores como se muestran en la UI
            display_dst_addr = p.dst_addr
            display_service = p.service
            if p.raw_data:
                # Destination: primero intenta raw_data, luego la columna
                raw_dest = p.raw_data.get('Destination')
                if raw_dest:
                    display_dst_addr = ', '.join(raw_dest) if isinstance(raw_dest, list) else str(raw_dest)
                    
            # Crear clave de grupo basada en valores MOSTRADOS
            group_parts = [
                str(p.device_id), p.vdom, p.src_intf, p.dst_intf,
                p.src_addr, display_dst_addr, display_service, p.action
            ]
            if not f_ignore_nat:
                group_parts.append(p.nat or '')
            group_key = hash(tuple(group_parts)) % 1000000  # Hash corto
            p._group_key = group_key
            if group_key not in duplicate_groups:
                duplicate_groups[group_key] = []
            duplicate_groups[group_key].append(p)
    
    equipos = g.tenant_session.query(Equipo).all()
    
    # Get Unique VDOMs for Dropdown
    vdoms_query = g.tenant_session.query(Policy.vdom).distinct().order_by(Policy.vdom).all()
    distinct_vdoms = [r[0] for r in vdoms_query if r[0]]

    args_limpios = request.args.copy()
    for param in ['page', 'sort', 'order', 'per_page']:
        if param in args_limpios: args_limpios.pop(param)

    return render_template('policies/list.html', 
                           pagination=pagination, 
                           equipos=equipos,
                           distinct_vdoms=distinct_vdoms,
                           filters=args_limpios,
                           current_sort=sort_by,
                           current_order=order,
                           current_per_page=per_page,
                           duplicate_groups=duplicate_groups)

# ... (Resto de rutas igual: get_policy_details, generate_script) ...
@policy_bp.route('/<uuid:policy_uuid>/details', methods=['GET'])
@login_required
@company_required
@product_required('policy_explorer')
def get_policy_details(policy_uuid):
    policy = g.tenant_session.get(Policy, policy_uuid)
    if not policy:
        abort(404)
    return jsonify(policy.raw_data)

@policy_bp.route('/generate_script', methods=['POST'])
@login_required
@company_required
@product_required('policy_explorer')
def generate_script():
    action = request.form.get('action_type')
    selected_uuids = request.form.getlist('selected_policies')
    
    if not selected_uuids:
        flash("No seleccionaste ninguna política", "warning")
        return redirect(url_for('policy.list_policies'))
    
    policies = g.tenant_session.query(Policy).filter(Policy.uuid.in_(selected_uuids)).order_by(Policy.vdom).all()
    
    lines = [f"# Script Generado por ISSEC - Acción: {action.upper()}", ""]
    current_vdom = None
    
    for p in policies:
        if p.vdom != current_vdom:
            if current_vdom: lines.append("end")
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
        lines.append("end") # policy
        lines.append("end") # vdom
        
    content = "\n".join(lines)
    filename = f"script_{action}.conf"
    
    return Response(content, mimetype="text/plain", headers={"Content-disposition": f"attachment; filename={filename}"})