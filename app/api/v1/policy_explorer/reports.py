"""
Reports API Endpoints
/api/v1/reports/*
"""
from flask import request, jsonify, g, session, current_app, Response
from flask_login import login_required
from app.api.v1 import api_v1_bp
from app.models.equipo import Equipo
from app.models.policy import Policy
from app.models.vdom import VDOM
from app.models.history import PolicyHistory
from app.decorators import company_required
from app.extensions.db import db
from app.services.pdf_generator import PDFReportGenerator
from app.services.csv_generator import CsvReportGenerator
from sqlalchemy import or_, func, desc
import io
import os
from datetime import datetime
import uuid


@api_v1_bp.route('/reports/types', methods=['GET'])
@login_required
@company_required
def api_list_report_types():
    """
    Get available report types
    
    Returns:
        JSON with report types and descriptions
    """
    report_types = [
        {
            'id': 'device_summary',
            'name': 'Resumen de Dispositivo',
            'description': 'Información general del dispositivo, VDOMs e interfaces',
            'category': 'device'
        },
        {
            'id': 'policy_changes',
            'name': 'Historial de Cambios',
            'description': 'Historial de cambios en políticas',
            'category': 'history'
        },
        {
            'id': 'zero_usage',
            'name': 'Reglas Sin Uso',
            'description': 'Políticas con 0 hits o 0 bytes',
            'category': 'security'
        },
        {
            'id': 'insecure',
            'name': 'Políticas Inseguras',
            'description': 'Políticas con ANY en origen, destino y servicio',
            'category': 'security'
        },
        {
            'id': 'duplicates',
            'name': 'Posibles Duplicados',
            'description': 'Políticas con configuración idéntica en el mismo VDOM',
            'category': 'optimization'
        },
        {
            'id': 'by_service',
            'name': 'Inventario por Servicio',
            'description': 'Todas las políticas ordenadas por servicio',
            'category': 'inventory'
        },
        {
            'id': 'any_source',
            'name': 'Origen ANY',
            'description': 'Políticas ACCEPT con origen ANY',
            'category': 'security'
        },
        {
            'id': 'any_dest',
            'name': 'Destino ANY',
            'description': 'Políticas ACCEPT con destino ANY',
            'category': 'security'
        },
        {
            'id': 'any_service',
            'name': 'Servicio ANY',
            'description': 'Políticas ACCEPT con servicio ANY',
            'category': 'security'
        },
        {
            'id': 'no_logging',
            'name': 'Sin Logging',
            'description': 'Políticas sin logging habilitado',
            'category': 'security'
        },
        {
            'id': 'disabled_policies',
            'name': 'Políticas Deshabilitadas',
            'description': 'Políticas con status disabled',
            'category': 'optimization'
        },
        {
            'id': 'no_ips',
            'name': 'Sin Perfil IPS',
            'description': 'Políticas ACCEPT sin perfil IPS',
            'category': 'security'
        },
        {
            'id': 'no_av',
            'name': 'Sin Antivirus',
            'description': 'Políticas ACCEPT sin perfil antivirus',
            'category': 'security'
        },
        {
            'id': 'no_ssl_inspection',
            'name': 'Sin SSL Inspection',
            'description': 'Políticas ACCEPT sin inspección SSL',
            'category': 'security'
        }
    ]
    
    return jsonify({
        'success': True,
        'data': report_types
    })


@api_v1_bp.route('/reports/preview', methods=['POST'])
@login_required
@company_required
def api_preview_report():
    """
    Preview report data without generating PDF/CSV
    
    Request Body (JSON):
        device_id (uuid): Device ID
        report_type (str): Report type
        vdoms (list): Optional list of VDOMs
    
    Returns:
        JSON with policies matching report criteria
    """
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'JSON body required'}), 400
    
    device_id = data.get('device_id')
    report_type = data.get('report_type')
    vdom_list = data.get('vdoms', [])
    
    if not device_id or not report_type:
        return jsonify({
            'success': False,
            'error': 'device_id and report_type are required'
        }), 400
    
    try:
        device_id = uuid.UUID(device_id)
    except ValueError:
        return jsonify({
            'success': False,
            'error': 'Invalid device_id format'
        }), 400
    
    device = g.tenant_session.get(Equipo, device_id)
    if not device:
        return jsonify({'success': False, 'error': 'Device not found'}), 404
    
    # Build query based on report type
    query = g.tenant_session.query(Policy).filter(Policy.device_id == device_id)
    
    if vdom_list:
        query = query.filter(Policy.vdom.in_(vdom_list))
    
    policies = apply_report_filters(query, report_type, device_id, g.tenant_session)
    
    # Serialize limited results for preview
    preview_data = []
    for p in policies[:100]:  # Limit preview to 100
        preview_data.append({
            'uuid': str(p.uuid),
            'policy_id': p.policy_id,
            'name': p.name,
            'vdom': p.vdom,
            'src_intf': p.src_intf,
            'dst_intf': p.dst_intf,
            'src_addr': p.src_addr,
            'dst_addr': p.dst_addr,
            'service': p.service,
            'action': p.action
        })
    
    return jsonify({
        'success': True,
        'data': preview_data,
        'total_count': len(policies),
        'preview_count': len(preview_data),
        'report_type': report_type,
        'device': {
            'id': str(device.id),
            'hostname': device.hostname,
            'nombre': device.nombre
        }
    })


@api_v1_bp.route('/reports/generate', methods=['POST'])
@login_required
@company_required
def api_generate_report():
    """
    Generate a report (PDF or CSV)
    
    Request Body (JSON):
        device_id (uuid): Device ID
        report_type (str): Report type
        format (str): 'pdf' or 'csv'
        vdoms (list): Optional list of VDOMs
        custom_filters (dict): For custom reports
    
    Returns:
        Binary file (PDF or CSV)
    """
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'JSON body required'}), 400
    
    device_id = data.get('device_id')
    report_type = data.get('report_type')
    output_format = data.get('format', 'pdf')
    vdom_list = data.get('vdoms', [])
    
    if not device_id or not report_type:
        return jsonify({
            'success': False,
            'error': 'device_id and report_type are required'
        }), 400
    
    try:
        device_id = uuid.UUID(device_id)
    except ValueError:
        return jsonify({'success': False, 'error': 'Invalid device_id'}), 400
    
    device = g.tenant_session.get(Equipo, device_id)
    if not device:
        return jsonify({'success': False, 'error': 'Device not found'}), 404
    
    # Build query
    query = g.tenant_session.query(Policy).filter(Policy.device_id == device_id)
    if vdom_list:
        query = query.filter(Policy.vdom.in_(vdom_list))
    
    policies = apply_report_filters(query, report_type, device_id, g.tenant_session)
    
    # Prepare output
    buffer = io.BytesIO()
    logo_path = os.path.join(os.getcwd(), 'app', 'static', 'img', 'issec.png')
    
    # Get company info
    from app.models.core import Company
    company_id = session.get('company_id')
    company_logo_path = None
    company_name = None
    if company_id:
        company = Company.query.get(company_id)
        if company:
            company_name = company.name
            if company.logo:
                custom_logo = os.path.join(current_app.root_path, 'static', 'uploads', company.logo)
                if os.path.exists(custom_logo):
                    company_logo_path = custom_logo
    
    title = get_report_title(report_type)
    filename = f"{report_type}_{device.nombre}_{datetime.now().strftime('%Y%m%d')}"
    
    filter_info = {
        'Tipo de Reporte': title,
        'Equipo': device.hostname or device.nombre,
        'VDOMs': ', '.join(vdom_list) if vdom_list else 'Todos',
    }
    
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


def apply_report_filters(query, report_type, device_id, tenant_session):
    """Apply filters based on report type and return policies"""
    
    if report_type == 'zero_usage':
        query = query.filter(or_(Policy.bytes_int == 0, Policy.hit_count == 0))
        return query.order_by(Policy.policy_id).all()
    
    elif report_type == 'insecure':
        query = query.filter(
            Policy.action == 'ACCEPT',
            or_(Policy.src_addr.ilike('%all%'), Policy.src_addr.ilike('%any%')),
            or_(Policy.dst_addr.ilike('%all%'), Policy.dst_addr.ilike('%any%')),
            or_(Policy.service.ilike('%ALL%'), Policy.service.ilike('%ANY%'))
        )
        return query.order_by(Policy.policy_id).all()
    
    elif report_type == 'duplicates':
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
        
        subquery = tenant_session.query(*group_cols)\
            .filter(Policy.device_id == device_id)\
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
        return query.order_by(Policy.vdom, Policy.service, Policy.src_addr).all()
    
    elif report_type == 'by_service':
        return query.order_by(Policy.service.asc()).all()
    
    elif report_type == 'any_source':
        query = query.filter(
            Policy.action == 'ACCEPT',
            or_(Policy.src_addr.ilike('%all%'), Policy.src_addr.ilike('%any%'))
        )
        return query.order_by(Policy.policy_id).all()
    
    elif report_type == 'any_dest':
        query = query.filter(
            Policy.action == 'ACCEPT',
            or_(Policy.dst_addr.ilike('%all%'), Policy.dst_addr.ilike('%any%'))
        )
        return query.order_by(Policy.policy_id).all()
    
    elif report_type == 'any_service':
        query = query.filter(
            Policy.action == 'ACCEPT',
            or_(Policy.service.ilike('%ALL%'), Policy.service.ilike('%ANY%'))
        )
        return query.order_by(Policy.policy_id).all()
    
    elif report_type == 'no_logging':
        query = query.filter(
            or_(
                Policy.raw_data['logtraffic'].astext == 'disable',
                Policy.raw_data['logtraffic'].astext == 'disabled',
                ~Policy.raw_data.has_key('logtraffic')
            )
        )
        return query.order_by(Policy.policy_id).all()
    
    elif report_type == 'disabled_policies':
        query = query.filter(
            or_(
                Policy.raw_data['Status'].astext.ilike('%disable%'),
                Policy.raw_data['status'].astext.ilike('%disable%')
            )
        )
        return query.order_by(Policy.policy_id).all()
    
    elif report_type == 'no_ips':
        query = query.filter(
            Policy.action == 'ACCEPT',
            or_(
                ~Policy.raw_data.has_key('ips-sensor'),
                Policy.raw_data['ips-sensor'].astext == ''
            )
        )
        return query.order_by(Policy.policy_id).all()
    
    elif report_type == 'no_av':
        query = query.filter(
            Policy.action == 'ACCEPT',
            or_(
                ~Policy.raw_data.has_key('av-profile'),
                Policy.raw_data['av-profile'].astext == ''
            )
        )
        return query.order_by(Policy.policy_id).all()
    
    elif report_type == 'no_ssl_inspection':
        query = query.filter(
            Policy.action == 'ACCEPT',
            or_(
                ~Policy.raw_data.has_key('ssl-ssh-profile'),
                Policy.raw_data['ssl-ssh-profile'].astext == ''
            )
        )
        return query.order_by(Policy.policy_id).all()
    
    else:
        return query.all()


def get_report_title(report_type):
    """Get human-readable title for report type"""
    titles = {
        'device_summary': 'Resumen de Dispositivo',
        'policy_changes': 'Historial de Cambios de Políticas',
        'zero_usage': 'Reporte: Reglas Sin Uso (0 Hits / 0 Bytes)',
        'insecure': 'Reporte: Políticas Inseguras (All-All)',
        'duplicates': 'Reporte: Posibles Duplicados (Mismo VDOM)',
        'by_service': 'Reporte: Inventario por Servicio',
        'any_source': 'Reporte: Políticas con Origen ANY',
        'any_dest': 'Reporte: Políticas con Destino ANY',
        'any_service': 'Reporte: Políticas con Servicio ANY',
        'no_logging': 'Reporte: Políticas Sin Logging',
        'disabled_policies': 'Reporte: Políticas Deshabilitadas',
        'no_ips': 'Reporte: Políticas Sin Perfil IPS',
        'no_av': 'Reporte: Políticas Sin Antivirus',
        'no_ssl_inspection': 'Reporte: Políticas Sin SSL Inspection'
    }
    return titles.get(report_type, 'Reporte de Seguridad')
