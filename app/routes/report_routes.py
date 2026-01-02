from flask import Blueprint, render_template, request, Response, flash, g, session, current_app
from flask_login import login_required
from app.models.equipo import Equipo
from app.models.policy import Policy
from app.models.vdom import VDOM
from app.models.history import PolicyHistory
from app.extensions.db import db
from app.services.pdf_generator import PDFReportGenerator
from sqlalchemy import or_, func, desc
from app.decorators import company_required
import io
import os
from datetime import datetime
import uuid

report_bp = Blueprint('report', __name__, url_prefix='/reports')

@report_bp.route('/', methods=['GET'])
@login_required
@company_required
def index():
    equipos = g.tenant_session.query(Equipo).all()
    return render_template('reports/index.html', equipos=equipos)

@report_bp.route('/generate', methods=['POST'])
@login_required
@company_required
def generate_pdf():
    device_id = request.form.get('device_id')
    report_type = request.form.get('report_type')
    # Get multiple VDOMs from multi-select
    vdom_list = request.form.getlist('vdom')  # Returns list of selected VDOMs
    vdom_list = [v for v in vdom_list if v]  # Remove empty values
    
    if not device_id or not report_type:
        flash("Debe seleccionar un equipo y un tipo de reporte", "warning")
        return render_template('reports/index.html', equipos=g.tenant_session.query(Equipo).all())

    try:
        if isinstance(device_id, str):
            device_id = uuid.UUID(device_id)
            
        device = g.tenant_session.get(Equipo, device_id)
        if not device:
            flash("Equipo no encontrado", "danger")
            return render_template('reports/index.html', equipos=g.tenant_session.query(Equipo).all())
    except ValueError:
        flash("ID de equipo inválido", "danger")
        return render_template('reports/index.html', equipos=g.tenant_session.query(Equipo).all())
    
    # vdom_list is now a list (can be empty if "all" VDOMs selected)
    
    # Common setup
    buffer = io.BytesIO()
    logo_path = os.path.join(os.getcwd(), 'app', 'static', 'img', 'issec.png')
    company_logo_path = None
    company_name = None
    
    from app.models.core import Company
    company_id = session.get('company_id')
    if company_id:
        company = Company.query.get(company_id)
        if company:
            company_name = company.name
            if company.logo:
                custom_logo = os.path.join(current_app.root_path, 'static', 'uploads', company.logo)
                if os.path.exists(custom_logo):
                    company_logo_path = custom_logo
    
    filename = f"{report_type}_{device.nombre}_{datetime.now().strftime('%Y%m%d')}"
    
    # === DEVICE SUMMARY REPORT ===
    if report_type == 'device_summary':
        title = f"Resumen de Dispositivo - {device.hostname or device.nombre}"
        
        vdoms = g.tenant_session.query(VDOM).filter_by(device_id=device.id).all()
        interfaces = device.config_data.get('interfaces', []) if device.config_data else []
        
        pdf = PDFReportGenerator(buffer, logo_path, company_logo_path, company_name)
        pdf.generate_device_report(device, vdoms, interfaces, title)
        
        buffer.seek(0)
        return Response(buffer, mimetype='application/pdf',
                        headers={"Content-Disposition": f"attachment;filename={filename}.pdf"})
    
    # === POLICY CHANGES REPORT ===
    if report_type == 'policy_changes':
        title = f"Historial de Cambios de Políticas - {device.hostname or device.nombre}"
        
        query = g.tenant_session.query(PolicyHistory).filter_by(device_id=device.id)
        if vdom_list:
            query = query.filter(PolicyHistory.vdom.in_(vdom_list))
        
        all_history = query.order_by(desc(PolicyHistory.change_date)).limit(500).all()
        
        # Group by session
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
        
        session_list = sorted(sessions.values(), key=lambda x: x['date'], reverse=True)
        
        pdf = PDFReportGenerator(buffer, logo_path, company_logo_path, company_name)
        pdf.generate_history_report(device, session_list, title, vdom_list)
        
        buffer.seek(0)
        return Response(buffer, mimetype='application/pdf',
                        headers={"Content-Disposition": f"attachment;filename={filename}.pdf"})
    
    # === POLICY REPORTS ===
    query = g.tenant_session.query(Policy).filter(Policy.device_id == device.id)
    
    if vdom_list:
        query = query.filter(Policy.vdom.in_(vdom_list))
    
    title = "Reporte de Seguridad"
    
    if report_type == 'zero_usage':
        title = "Reporte: Reglas Sin Uso (0 Hits / 0 Bytes)"
        query = query.filter(or_(Policy.bytes_int == 0, Policy.hit_count == 0))
        policies = query.order_by(Policy.policy_id).all()

    elif report_type == 'insecure':
        title = "Reporte: Políticas Inseguras (All-All)"
        query = query.filter(
            Policy.action == 'ACCEPT',
            or_(Policy.src_addr.ilike('%all%'), Policy.src_addr.ilike('%any%')),
            or_(Policy.dst_addr.ilike('%all%'), Policy.dst_addr.ilike('%any%')),
            or_(Policy.service.ilike('%ALL%'), Policy.service.ilike('%ANY%'))
        )
        policies = query.order_by(Policy.policy_id).all()

    elif report_type == 'duplicates':
        title = "Reporte: Posibles Duplicados (Mismo VDOM)"
        # Buscar políticas con misma config en el MISMO VDOM
        # Usar raw_data.Destination si existe (consistencia con UI)
        json_dest = func.coalesce(
            Policy.raw_data['Destination'].astext,
            Policy.dst_addr
        ).label('dest_display')
        
        group_cols = [
            Policy.vdom,
            Policy.src_intf, Policy.dst_intf, 
            Policy.src_addr, json_dest, 
            Policy.service, Policy.action
        ]
        
        # Subquery: grupos con MÁS DE UNA política (duplicados en mismo VDOM)
        subquery = g.tenant_session.query(*group_cols)\
            .filter(Policy.device_id == device.id)\
            .group_by(*group_cols)\
            .having(func.count(Policy.uuid) > 1)\
            .subquery()

        json_dest_compare = func.coalesce(
            Policy.raw_data['Destination'].astext,
            Policy.dst_addr
        )

        query = query.join(subquery, db.and_(
            Policy.vdom == subquery.c.vdom,
            Policy.src_intf == subquery.c.src_intf,
            Policy.dst_intf == subquery.c.dst_intf,
            Policy.src_addr == subquery.c.src_addr,
            json_dest_compare == subquery.c.dest_display,
            Policy.service == subquery.c.service,
            Policy.action == subquery.c.action
        ))
        policies = query.order_by(Policy.vdom, Policy.service, Policy.src_addr).all()

    elif report_type == 'by_service':
        title = "Reporte: Inventario por Servicio"
        policies = query.order_by(Policy.service.asc()).all()

    # === NEW INSECURE POLICY REPORTS ===
    elif report_type == 'any_source':
        title = "Reporte: Políticas con Origen ANY"
        query = query.filter(
            Policy.action == 'ACCEPT',
            or_(Policy.src_addr.ilike('%all%'), Policy.src_addr.ilike('%any%'))
        )
        policies = query.order_by(Policy.policy_id).all()

    elif report_type == 'any_dest':
        title = "Reporte: Políticas con Destino ANY"
        query = query.filter(
            Policy.action == 'ACCEPT',
            or_(Policy.dst_addr.ilike('%all%'), Policy.dst_addr.ilike('%any%'))
        )
        policies = query.order_by(Policy.policy_id).all()

    elif report_type == 'any_service':
        title = "Reporte: Políticas con Servicio ANY"
        query = query.filter(
            Policy.action == 'ACCEPT',
            or_(Policy.service.ilike('%ALL%'), Policy.service.ilike('%ANY%'))
        )
        policies = query.order_by(Policy.policy_id).all()

    elif report_type == 'no_logging':
        title = "Reporte: Políticas Sin Logging"
        # Check raw_data for logtraffic field
        query = query.filter(
            or_(
                Policy.raw_data['logtraffic'].astext == 'disable',
                Policy.raw_data['logtraffic'].astext == 'disabled',
                ~Policy.raw_data.has_key('logtraffic')
            )
        )
        policies = query.order_by(Policy.policy_id).all()

    elif report_type == 'disabled_policies':
        title = "Reporte: Políticas Deshabilitadas"
        query = query.filter(
            or_(
                Policy.raw_data['Status'].astext.ilike('%disable%'),
                Policy.raw_data['status'].astext.ilike('%disable%')
            )
        )
        policies = query.order_by(Policy.policy_id).all()

    elif report_type == 'no_ips':
        title = "Reporte: Políticas Sin Perfil IPS"
        query = query.filter(
            Policy.action == 'ACCEPT',
            or_(
                ~Policy.raw_data.has_key('ips-sensor'),
                Policy.raw_data['ips-sensor'].astext == ''
            )
        )
        policies = query.order_by(Policy.policy_id).all()

    elif report_type == 'no_av':
        title = "Reporte: Políticas Sin Antivirus"
        query = query.filter(
            Policy.action == 'ACCEPT',
            or_(
                ~Policy.raw_data.has_key('av-profile'),
                Policy.raw_data['av-profile'].astext == ''
            )
        )
        policies = query.order_by(Policy.policy_id).all()

    elif report_type == 'no_ssl_inspection':
        title = "Reporte: Políticas Sin SSL Inspection"
        query = query.filter(
            Policy.action == 'ACCEPT',
            or_(
                ~Policy.raw_data.has_key('ssl-ssh-profile'),
                Policy.raw_data['ssl-ssh-profile'].astext == ''
            )
        )
        policies = query.order_by(Policy.policy_id).all()

    elif report_type == 'custom':
        # Custom report with dynamic filters
        custom_name = request.form.get('custom_name', '').strip()
        title = f"Reporte Personalizado: {custom_name}" if custom_name else "Reporte Personalizado"
        
        # Action filter
        custom_action = request.form.get('custom_action', '').strip()
        if custom_action:
            query = query.filter(Policy.action == custom_action)
        
        # Source Interface filter
        custom_src_intf = request.form.get('custom_src_intf', '').strip()
        if custom_src_intf:
            query = query.filter(Policy.src_intf.ilike(f'%{custom_src_intf}%'))
        
        # Source Address filter
        custom_src_addr = request.form.get('custom_src_addr', '').strip()
        if custom_src_addr:
            query = query.filter(Policy.src_addr.ilike(f'%{custom_src_addr}%'))
        
        # Destination Interface filter
        custom_dst_intf = request.form.get('custom_dst_intf', '').strip()
        if custom_dst_intf:
            query = query.filter(Policy.dst_intf.ilike(f'%{custom_dst_intf}%'))
        
        # Destination Address filter
        custom_dst_addr = request.form.get('custom_dst_addr', '').strip()
        if custom_dst_addr:
            query = query.filter(Policy.dst_addr.ilike(f'%{custom_dst_addr}%'))
        
        # Service filter
        custom_svc = request.form.get('custom_svc', '').strip()
        if custom_svc:
            query = query.filter(Policy.service.ilike(f'%{custom_svc}%'))
        
        # Traffic filter
        custom_traffic = request.form.get('custom_traffic', '').strip()
        if custom_traffic == 'zero':
            query = query.filter(Policy.bytes_int == 0)
        elif custom_traffic == 'nonzero':
            query = query.filter(Policy.bytes_int > 0)
        
        # Logging filter
        custom_logging = request.form.get('custom_logging', '').strip()
        if custom_logging == 'disabled':
            query = query.filter(
                or_(
                    Policy.raw_data['logtraffic'].astext == 'disable',
                    ~Policy.raw_data.has_key('logtraffic')
                )
            )
        elif custom_logging == 'enabled':
            query = query.filter(
                Policy.raw_data['logtraffic'].astext != 'disable',
                Policy.raw_data.has_key('logtraffic')
            )
        
        # IPS filter
        custom_ips = request.form.get('custom_ips', '').strip()
        if custom_ips == 'missing':
            query = query.filter(
                or_(
                    ~Policy.raw_data.has_key('ips-sensor'),
                    Policy.raw_data['ips-sensor'].astext == ''
                )
            )
        elif custom_ips == 'present':
            query = query.filter(
                Policy.raw_data.has_key('ips-sensor'),
                Policy.raw_data['ips-sensor'].astext != ''
            )
        
        # AV filter
        custom_av = request.form.get('custom_av', '').strip()
        if custom_av == 'missing':
            query = query.filter(
                or_(
                    ~Policy.raw_data.has_key('av-profile'),
                    Policy.raw_data['av-profile'].astext == ''
                )
            )
        elif custom_av == 'present':
            query = query.filter(
                Policy.raw_data.has_key('av-profile'),
                Policy.raw_data['av-profile'].astext != ''
            )
        
        # SSL filter
        custom_ssl = request.form.get('custom_ssl', '').strip()
        if custom_ssl == 'missing':
            query = query.filter(
                or_(
                    ~Policy.raw_data.has_key('ssl-ssh-profile'),
                    Policy.raw_data['ssl-ssh-profile'].astext == ''
                )
            )
        elif custom_ssl == 'present':
            query = query.filter(
                Policy.raw_data.has_key('ssl-ssh-profile'),
                Policy.raw_data['ssl-ssh-profile'].astext != ''
            )
        
        # Duplicates filter - busca políticas con misma config en el MISMO VDOM
        custom_dupes = request.form.get('custom_duplicates', '').strip()
        if custom_dupes == 'on':
            custom_ignore_nat = request.form.get('custom_ignore_nat', '').strip() == 'on'
            
            group_cols = [
                Policy.vdom,
                Policy.src_intf, Policy.dst_intf,
                Policy.src_addr, Policy.dst_addr,
                Policy.service, Policy.action
            ]
            if not custom_ignore_nat:
                group_cols.append(Policy.nat)
            
            # Subquery: grupos con MÁS DE UNA política (duplicados en mismo VDOM)
            dup_subquery = g.tenant_session.query(*group_cols)\
                .filter(Policy.device_id == device.id)\
                .group_by(*group_cols)\
                .having(func.count(Policy.uuid) > 1)\
                .subquery()
            
            dup_conditions = [
                Policy.vdom == dup_subquery.c.vdom,
                Policy.src_intf == dup_subquery.c.src_intf,
                Policy.dst_intf == dup_subquery.c.dst_intf,
                Policy.src_addr == dup_subquery.c.src_addr,
                Policy.dst_addr == dup_subquery.c.dst_addr,
                Policy.service == dup_subquery.c.service,
                Policy.action == dup_subquery.c.action
            ]
            if not custom_ignore_nat:
                dup_conditions.append(Policy.nat == dup_subquery.c.nat)
            
            query = query.join(dup_subquery, db.and_(*dup_conditions))
        
        policies = query.order_by(Policy.policy_id).all()

    else:
        policies = []

    from app.services.csv_generator import CsvReportGenerator

    output_format = request.form.get('format', 'pdf')

    # Build filter_info for cover page - now for ALL reports
    filter_info = {
        'Tipo de Reporte': title,
        'Equipo': device.hostname or device.nombre,
        'VDOMs': ', '.join(vdom_list) if vdom_list else 'Todos',
    }
    
    # Add extra filters for custom reports
    if report_type == 'custom':
        custom_filters = {
            'Origen Interface': request.form.get('custom_src_intf', '').strip() or None,
            'Origen Address': request.form.get('custom_src_addr', '').strip() or None,
            'Destino Interface': request.form.get('custom_dst_intf', '').strip() or None,
            'Destino Address': request.form.get('custom_dst_addr', '').strip() or None,
            'Servicio': request.form.get('custom_svc', '').strip() or None,
            'Acción': request.form.get('custom_action', '').strip() or None,
        }
        filter_info.update(custom_filters)

    if output_format == 'csv':
        csv_gen = CsvReportGenerator(buffer)
        csv_gen.generate(device, policies, report_type)
        mimetype = 'text/csv'
        filename += ".csv"
    else:
        pdf = PDFReportGenerator(buffer, logo_path, company_logo_path, company_name)
        pdf.generate(device, policies, report_type, title, vdom_list, filter_info)
        mimetype = 'application/pdf'
        filename += ".pdf"
    
    buffer.seek(0)
    
    return Response(buffer, mimetype=mimetype, 
                    headers={"Content-Disposition": f"attachment;filename={filename}"})