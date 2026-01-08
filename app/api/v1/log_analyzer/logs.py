"""
Logs API Endpoints
/api/v1/logs/*

Log Analyzer for FortiAnalyzer logs - analyzes traffic patterns
and generates security recommendations
"""
from flask import request, jsonify, g, session, make_response, current_app
from app.api.v1 import api_v1_bp
from app.models.log_entry import LogEntry, LogImportSession, SecurityRecommendation
from app.models.equipo import Equipo
from app.decorators import api_login_required, api_company_required, api_product_required
from app.extensions.db import db
from app.services.log_parser import FortiLogParser, LogAnalyzer
from app.services.pdf_generator import PDFReportGenerator
from app.models.core import Company
from sqlalchemy import func, desc, and_, or_
from datetime import datetime, timedelta
import uuid
import csv
import io
import os


@api_v1_bp.route('/logs', methods=['GET'])
@api_login_required
@api_company_required
@api_product_required('log_analyzer')
def api_list_logs():
    """
    List/search logs with filters
    
    Query Parameters:
        page (int): Page number
        per_page (int): Items per page (max 500)
        device_id (uuid): Filter by device
        vdom (str): Filter by VDOM
        log_type (str): traffic, event, ips, etc.
        action (str): accept, deny, etc.
        src_ip (str): Source IP filter
        dst_ip (str): Destination IP filter
        policy_id (int): Filter by policy ID
        start_date (str): ISO date filter
        end_date (str): ISO date filter
        q (str): General search
    
    Returns:
        JSON with logs and pagination
    """
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 32, type=int)
    if per_page not in [8, 16, 32, 64, 128, 256, 512]:
        per_page = 32
    
    # Build query
    query = g.tenant_session.query(LogEntry)
    
    # Filters
    device_id = request.args.get('device_id')
    if device_id:
        query = query.filter(LogEntry.device_id == device_id)
    
    vdom = request.args.get('vdom')
    if vdom:
        query = query.filter(LogEntry.vdom == vdom)
    
    log_type = request.args.get('log_type')
    if log_type:
        query = query.filter(LogEntry.log_type == log_type)
    
    action = request.args.get('action')
    if action:
        query = query.filter(LogEntry.action == action)
    
    src_ip = request.args.get('src_ip')
    if src_ip:
        query = query.filter(LogEntry.src_ip.ilike(f'%{src_ip}%'))
    
    dst_ip = request.args.get('dst_ip')
    if dst_ip:
        query = query.filter(LogEntry.dst_ip.ilike(f'%{dst_ip}%'))
    
    policy_id = request.args.get('policy_id', type=int)
    if policy_id:
        query = query.filter(LogEntry.policy_id == policy_id)
    
    start_date = request.args.get('start_date')
    if start_date:
        try:
            start_dt = datetime.fromisoformat(start_date)
            query = query.filter(LogEntry.timestamp >= start_dt)
        except ValueError:
            pass
    
    end_date = request.args.get('end_date')
    if end_date:
        try:
            end_dt = datetime.fromisoformat(end_date)
            query = query.filter(LogEntry.timestamp <= end_dt)
        except ValueError:
            pass
    
    # General search
    q = request.args.get('q')
    if q:
        query = query.filter(or_(
            LogEntry.src_ip.ilike(f'%{q}%'),
            LogEntry.dst_ip.ilike(f'%{q}%'),
            LogEntry.service.ilike(f'%{q}%'),
            LogEntry.app.ilike(f'%{q}%')
        ))
    
    # Order by timestamp desc
    query = query.order_by(desc(LogEntry.timestamp))
    
    # Pagination
    total = query.count()
    logs = query.offset((page - 1) * per_page).limit(per_page).all()
    
    data = [serialize_log(log) for log in logs]
    
    return jsonify({
        'success': True,
        'data': data,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page
        }
    })


@api_v1_bp.route('/logs/<uuid:log_id>', methods=['GET'])
@api_login_required
@api_company_required
@api_product_required('log_analyzer')
def api_get_log(log_id):
    """
    Get a single log entry with full details
    """
    log = g.tenant_session.get(LogEntry, log_id)
    if not log:
        return jsonify({'success': False, 'error': 'Log not found'}), 404
    
    data = serialize_log(log)
    data['raw_data'] = log.raw_data
    
    return jsonify({
        'success': True,
        'data': data
    })


@api_v1_bp.route('/logs/import', methods=['POST'])
@api_login_required
@api_company_required
@api_product_required('log_analyzer')
def api_import_logs():
    """
    Import logs from file
    
    The device is auto-detected from the 'devid' (serial) field in the log entries.
    
    Request Body (multipart/form-data):
        file (file): Log file (FortiAnalyzer CSV export)
    
    Returns:
        JSON with import stats and initial analysis
    """
    file = request.files.get('file')
    
    if not file:
        return jsonify({
            'success': False,
            'error': 'file is required'
        }), 400
    
    try:
        content = file.read().decode('utf-8', errors='ignore')
        
        # Parse logs first to get the device serial
        raw_entries = FortiLogParser.parse_file(content)
        
        if not raw_entries:
            return jsonify({
                'success': False,
                'error': 'No valid log entries found in file. Check file format.'
            }), 400
        
        # Auto-detect device from devid in logs
        devid = None
        for entry in raw_entries[:10]:  # Check first 10 entries
            devid = entry.get('devid')
            if devid:
                break
        
        if not devid:
            return jsonify({
                'success': False,
                'error': 'Could not find device serial (devid) in log entries'
            }), 400
        
        # Find device by serial
        device = g.tenant_session.query(Equipo).filter(Equipo.serial == devid).first()
        
        if not device:
            # Try matching by segundo_serial (HA pair)
            device = g.tenant_session.query(Equipo).filter(Equipo.segundo_serial == devid).first()
        
        if not device:
            return jsonify({
                'success': False,
                'error': f'Device with serial "{devid}" not found. Please register the device first.'
            }), 404
        
        device_uuid = device.id
        
        # Create import session
        import_session = LogImportSession(
            device_id=device_uuid,
            filename=file.filename,
            log_count=len(raw_entries)
        )
        g.tenant_session.add(import_session)
        g.tenant_session.flush()
        
        # Pre-fetch policies for mapping (policy_id + vdom -> uuid)
        from app.models.policy import Policy
        existing_policies = g.tenant_session.query(Policy.uuid, Policy.policy_id, Policy.vdom).filter(
            Policy.device_id == device_uuid
        ).all()
        
        # Create map: (str(policy_id), vdom) -> uuid
        policy_map = {}
        for p_uuid, p_id, p_vdom in existing_policies:
            if p_id:
                policy_map[(str(p_id), p_vdom)] = p_uuid
        
        # Normalize and store logs
        normalized_logs = []
        timestamps = []
        
        for raw_entry in raw_entries:
            normalized = FortiLogParser.normalize_entry(raw_entry)
            normalized_logs.append(normalized)
            
            # Lookup Policy UUID
            p_uuid = None
            if normalized.get('policy_id'):
                key = (str(normalized['policy_id']), normalized.get('vdom', 'root'))
                p_uuid = policy_map.get(key)
            
            log_entry = LogEntry(
                device_id=device_uuid,
                import_session_id=import_session.id,
                log_id=normalized.get('log_id'),
                log_type=normalized.get('log_type'),
                subtype=normalized.get('subtype'),
                level=normalized.get('level'),
                timestamp=normalized.get('timestamp'),
                itime=normalized.get('itime'),
                eventtime=normalized.get('eventtime'),
                devid=normalized.get('devid'),
                devname=normalized.get('devname'),
                vdom=normalized.get('vdom'),
                src_intf=normalized.get('src_intf'),
                src_intf_role=normalized.get('src_intf_role'),
                src_ip=normalized.get('src_ip'),
                src_port=normalized.get('src_port'),
                src_country=normalized.get('src_country'),
                src_city=normalized.get('src_city'),
                src_mac=normalized.get('src_mac'),
                dst_intf=normalized.get('dst_intf'),
                dst_intf_role=normalized.get('dst_intf_role'),
                dst_ip=normalized.get('dst_ip'),
                dst_port=normalized.get('dst_port'),
                dst_country=normalized.get('dst_country'),
                dst_city=normalized.get('dst_city'),
                policy_id=normalized.get('policy_id'),
                policy_uuid=p_uuid, # Linked UUID
                policy_type=normalized.get('policy_type'),
                action=normalized.get('action'),
                protocol=normalized.get('protocol'),
                service=normalized.get('service'),
                app=normalized.get('app'),
                app_cat=normalized.get('app_cat'),
                sent_bytes=normalized.get('sent_bytes'),
                rcvd_bytes=normalized.get('rcvd_bytes'),
                sent_pkts=normalized.get('sent_pkts'),
                rcvd_pkts=normalized.get('rcvd_pkts'),
                duration=normalized.get('duration'),
                session_id=normalized.get('session_id'),
                nat_type=normalized.get('nat_type'),
                raw_data=normalized.get('raw_data')
            )
            g.tenant_session.add(log_entry)
            
            if normalized.get('timestamp'):
                timestamps.append(normalized['timestamp'])
        
        # Update session with date range
        if timestamps:
            import_session.start_date = min(timestamps)
            import_session.end_date = max(timestamps)
        
        # Analyze logs
        analysis = LogAnalyzer.analyze_logs(normalized_logs)
        import_session.stats = analysis['stats']
        
        # --- AI Analysis Integration ---
        from flask import current_app
        from app.services.ai_service import AIService
        from app.models.core import Company
        
        # Determine API Key: Check Company settings first, then Global config
        ai_key = None
        company_id = session.get('company_id')
        if company_id:
             company = db.session.get(Company, company_id) # Query Central DB
             if company and company.gemini_api_key:
                 ai_key = company.gemini_api_key
        
        if not ai_key:
             ai_key = current_app.config.get('GEMINI_API_KEY')

        if ai_key:
            try:
                # Filter stats to reduce token usage
                ai_stats = {k: v for k, v in analysis['stats'].items() if k not in ['denied_connections', 'high_volume_sessions']}
                # Take a sample of interesting logs
                interesting_logs = analysis['stats'].get('denied_connections', [])[:20]
                
                # Pass key dynamically
                ai_result = AIService.analyze_security_logs(ai_stats, interesting_logs, api_key=ai_key)
                
                if 'recommendations' in ai_result:
                    # Map AI recommendations to our format
                    for ai_rec in ai_result['recommendations']:
                        analysis['recommendations'].append({
                            'category': 'ai_security',
                            'severity': ai_rec.get('severity', 'medium'),
                            'title': '[AI] ' + ai_rec.get('title', 'Security Insight'),
                            'description': ai_rec.get('description', ''),
                            'recommendation': ai_rec.get('action', ''),
                            'affected_count': 0 
                        })
            except Exception as e:
                current_app.logger.warning(f"AI Analysis failed: {e}")
        # -------------------------------

        # Store recommendations
        for rec in analysis['recommendations']:
            recommendation = SecurityRecommendation(
                device_id=device_uuid,
                category=rec['category'],
                severity=rec['severity'],
                title=rec['title'],
                description=rec['description'],
                recommendation=rec['recommendation'],
                related_policy_id=rec.get('related_policy_id'),
                affected_count=rec.get('affected_count', 0),
                evidence={'source': 'log_import', 'import_session_id': str(import_session.id), 'cli_remediation': rec.get('cli_remediation')}
            )
            g.tenant_session.add(recommendation)
        
        g.tenant_session.commit()
        
        return jsonify({
            'success': True,
            'import_session_id': str(import_session.id),
            'log_count': len(raw_entries),
            'date_range': {
                'start': import_session.start_date.isoformat() if import_session.start_date else None,
                'end': import_session.end_date.isoformat() if import_session.end_date else None
            },
            'analysis': analysis,
            'message': f'Importados {len(raw_entries)} logs con {len(analysis["recommendations"])} recomendaciones'
        })
        
    except Exception as e:
        g.tenant_session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_v1_bp.route('/logs/stats', methods=['GET'])
@api_login_required
@api_company_required
@api_product_required('log_analyzer')
def api_log_stats():
    """
    Get aggregated log statistics
    
    Query Parameters:
        device_id (uuid): Filter by device
        vdom (str): Filter by VDOM
        start_date (str): Start date
        end_date (str): End date
    
    Returns:
        JSON with aggregated statistics
    """
    # Build base filters
    filters = []
    
    device_id = request.args.get('device_id')
    if device_id:
        filters.append(LogEntry.device_id == device_id)
    
    vdom = request.args.get('vdom')
    if vdom:
        filters.append(LogEntry.vdom == vdom)
    
    # Date filters
    start_date = request.args.get('start_date')
    if start_date:
        try:
            filters.append(LogEntry.timestamp >= datetime.fromisoformat(start_date))
        except ValueError:
            pass
    
    end_date = request.args.get('end_date')
    if end_date:
        try:
            filters.append(LogEntry.timestamp <= datetime.fromisoformat(end_date))
        except ValueError:
            pass
    
    # Calculate stats
    base_query = g.tenant_session.query(LogEntry)
    if filters:
        base_query = base_query.filter(*filters)
    
    total_logs = base_query.count()
    
    # By action - apply filters
    action_query = g.tenant_session.query(
        LogEntry.action,
        func.count(LogEntry.id).label('count')
    )
    if filters:
        action_query = action_query.filter(*filters)
    action_stats = action_query.group_by(LogEntry.action).all()
    
    # By log type
    type_query = g.tenant_session.query(
        LogEntry.log_type,
        func.count(LogEntry.id).label('count')
    )
    if filters:
        type_query = type_query.filter(*filters)
    type_stats = type_query.group_by(LogEntry.log_type).all()
    
    # By VDOM
    vdom_query = g.tenant_session.query(
        LogEntry.vdom,
        func.count(LogEntry.id).label('count')
    )
    if filters:
        vdom_query = vdom_query.filter(*filters)
    vdom_stats = vdom_query.group_by(LogEntry.vdom).all()
    
    # Top policies
    policy_stats = g.tenant_session.query(
        LogEntry.policy_id,
        func.count(LogEntry.id).label('count'),
        func.sum(LogEntry.sent_bytes + LogEntry.rcvd_bytes).label('bytes')
    ).filter(LogEntry.policy_id.isnot(None))\
     .group_by(LogEntry.policy_id)\
     .order_by(desc('count'))\
     .limit(20).all()
    
    # Top source IPs
    top_sources = g.tenant_session.query(
        LogEntry.src_ip,
        func.count(LogEntry.id).label('count'),
        func.sum(LogEntry.sent_bytes).label('bytes')
    ).filter(LogEntry.src_ip.isnot(None))\
     .group_by(LogEntry.src_ip)\
     .order_by(desc('bytes'))\
     .limit(20).all()
    
    # Top destinations
    top_destinations = g.tenant_session.query(
        LogEntry.dst_ip,
        func.count(LogEntry.id).label('count'),
        func.sum(LogEntry.rcvd_bytes).label('bytes')
    ).filter(LogEntry.dst_ip.isnot(None))\
     .group_by(LogEntry.dst_ip)\
     .order_by(desc('bytes'))\
     .limit(20).all()
    
    # Top services
    service_stats = g.tenant_session.query(
        LogEntry.service,
        func.count(LogEntry.id).label('count')
    ).filter(LogEntry.service.isnot(None))\
     .group_by(LogEntry.service)\
     .order_by(desc('count'))\
     .limit(20).all()
    
    # v1.3.0 - By source interface
    src_intf_query = g.tenant_session.query(
        LogEntry.src_intf,
        func.count(LogEntry.id).label('count')
    ).filter(LogEntry.src_intf.isnot(None))
    if filters:
        src_intf_query = src_intf_query.filter(*filters)
    src_intf_stats = src_intf_query.group_by(LogEntry.src_intf).all()
    
    # v1.3.0 - By destination interface
    dst_intf_query = g.tenant_session.query(
        LogEntry.dst_intf,
        func.count(LogEntry.id).label('count')
    ).filter(LogEntry.dst_intf.isnot(None))
    if filters:
        dst_intf_query = dst_intf_query.filter(*filters)
    dst_intf_stats = dst_intf_query.group_by(LogEntry.dst_intf).all()
    
    return jsonify({
        'success': True,
        'data': {
            'total_logs': total_logs,
            'by_action': {r[0]: r[1] for r in action_stats if r[0]},
            'by_type': {r[0]: r[1] for r in type_stats if r[0]},
            'by_vdom': {r[0]: r[1] for r in vdom_stats if r[0]},
            'by_src_intf': {r[0]: r[1] for r in src_intf_stats if r[0]},
            'by_dst_intf': {r[0]: r[1] for r in dst_intf_stats if r[0]},
            'top_policies': [
                {'policy_id': r[0], 'count': r[1], 'bytes': r[2] or 0}
                for r in policy_stats
            ],
            'top_sources': [
                {'ip': r[0], 'count': r[1], 'bytes': r[2] or 0}
                for r in top_sources
            ],
            'top_destinations': [
                {'ip': r[0], 'count': r[1], 'bytes': r[2] or 0}
                for r in top_destinations
            ],
            'top_services': {r[0]: r[1] for r in service_stats if r[0]}
        }
    })


@api_v1_bp.route('/logs/recommendations', methods=['GET'])
@api_login_required
@api_company_required
@api_product_required('log_analyzer')
def api_list_recommendations():
    """
    Get security recommendations with pagination
    
    Query Parameters:
        device_id (uuid): Filter by device
        status (str): Filter by status
        severity (str): Filter by severity
        category (str): Filter by category
        page (int): Page number
        per_page (int): Items per page
    """
    from sqlalchemy import desc, case
    
    query = g.tenant_session.query(SecurityRecommendation)
    
    # Pagination params
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 8, type=int)
    allowed_per_page = [8, 16, 32, 64, 128, 256, 512]
    if per_page not in allowed_per_page:
        per_page = 8

    # Filters
    device_id = request.args.get('device_id')
    if device_id:
        query = query.filter(SecurityRecommendation.device_id == device_id)
    
    status = request.args.get('status')
    if status:
        query = query.filter(SecurityRecommendation.status == status)
    
    severity = request.args.get('severity')
    if severity:
        query = query.filter(SecurityRecommendation.severity == severity)
    
    category = request.args.get('category')
    if category:
        query = query.filter(SecurityRecommendation.category == category)
    
    # Order by severity (critical first) and date
    # Order by severity (critical first) and date
    severity_order = case(
        (SecurityRecommendation.severity == 'critical', 1),
        (SecurityRecommendation.severity == 'high', 2),
        (SecurityRecommendation.severity == 'medium', 3),
        (SecurityRecommendation.severity == 'low', 4),
        else_=5
    )
    
    # Calculate Total
    total = query.count()
    
    # Paginate manually
    import math
    pages = math.ceil(total / per_page)
    offset = (page - 1) * per_page
    
    recommendations = query.order_by(severity_order, desc(SecurityRecommendation.created_at))\
                           .limit(per_page).offset(offset).all()
    
    data = [{
        'id': str(r.id),
        'device_id': str(r.device_id),
        'category': r.category,
        'severity': r.severity,
        'title': r.title,
        'description': r.description,
        'recommendation': r.recommendation,
        'related_policy_id': r.related_policy_id,
        'related_vdom': r.related_vdom,
        'affected_count': r.affected_count,
        'status': r.status,
        'created_at': r.created_at.isoformat() if r.created_at else None,
        'cli_remediation': r.evidence.get('cli_remediation') if r.evidence else None
    } for r in recommendations]
    
    return jsonify({
        'success': True,
        'data': data,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': pages
        }
    })


@api_v1_bp.route('/logs/analyze', methods=['POST'])
@api_login_required
@api_company_required
@api_product_required('log_analyzer')
def api_run_ai_analysis():
    """
    Run AI analysis on imported logs with configurable parameters
    
    Request Body (JSON):
        analyze_denied (bool): Analyze denied connections
        analyze_high_volume (bool): Analyze high volume sessions
        analyze_geo (bool): Analyze by geolocation
        optimize_policies (bool): Suggest policy optimizations
        suggest_new_policies (bool): Suggest new policies
        threshold (str): Alert threshold (low, medium, high)
    
    Returns:
        JSON with analysis results
    """
    from flask import current_app
    from app.services.ai_service import AIService
    from app.models.core import Company
    from app.services.log_parser import LogAnalyzer
    
    data = request.get_json() or {}
    
    # Get AI parameters
    analyze_denied = data.get('analyze_denied', True)
    analyze_high_volume = data.get('analyze_high_volume', True)
    analyze_geo = data.get('analyze_geo', True)
    optimize_policies = data.get('optimize_policies', False)
    suggest_new_policies = data.get('suggest_new_policies', False)
    threshold = data.get('threshold', 'medium')
    
    # v1.3.0 - Segmentation filters
    filter_device_id = data.get('device_id')
    filter_vdom = data.get('vdom')
    filter_src_intf = data.get('src_intf')
    filter_dst_intf = data.get('dst_intf')
    
    # Get date range from request, default to last 30 days
    from datetime import datetime, timedelta
    
    days_back = data.get('days_back', 30)
    start_date = data.get('start_date')
    end_date = data.get('end_date')
    
    if start_date:
        try:
            cutoff = datetime.fromisoformat(start_date)
        except:
            cutoff = datetime.utcnow() - timedelta(days=days_back)
    else:
        cutoff = datetime.utcnow() - timedelta(days=days_back)
    
    query = g.tenant_session.query(LogEntry).filter(
        LogEntry.timestamp >= cutoff
    )
    
    if end_date:
        try:
            end_dt = datetime.fromisoformat(end_date)
            query = query.filter(LogEntry.timestamp <= end_dt)
        except:
            pass
    
    # v1.3.0 - Apply segmentation filters
    if filter_device_id:
        query = query.filter(LogEntry.device_id == filter_device_id)
    if filter_vdom:
        query = query.filter(LogEntry.vdom == filter_vdom)
    if filter_src_intf:
        query = query.filter(LogEntry.src_intf == filter_src_intf)
    if filter_dst_intf:
        query = query.filter(LogEntry.dst_intf == filter_dst_intf)
    
    logs = query.limit(10000).all()
    
    if not logs:
        filter_desc = []
        if filter_vdom:
            filter_desc.append(f"VDOM={filter_vdom}")
        if filter_src_intf:
            filter_desc.append(f"src_intf={filter_src_intf}")
        if filter_dst_intf:
            filter_desc.append(f"dst_intf={filter_dst_intf}")
        filter_str = ", ".join(filter_desc) if filter_desc else f"last {days_back} days"
        return jsonify({
            'success': False,
            'error': f'No logs found for analysis ({filter_str}). Adjust filters or import logs.'
        }), 400
    
    # Prepare normalized logs for analysis
    normalized_logs = []
    unique_policy_ids = set()
    device_ids = set()

    for log in logs:
        if log.policy_id:
            unique_policy_ids.add(str(log.policy_id))
        if log.device_id:
            device_ids.add(log.device_id)

        normalized_logs.append({
            'action': log.action,
            'src_ip': log.src_ip,
            'dst_ip': log.dst_ip,
            'src_country': log.src_country,
            'dst_country': log.dst_country,
            'policy_id': log.policy_id,
            'vdom': log.vdom,
            'service': log.service,
            'app': log.app,
            'sent_bytes': log.sent_bytes or 0,
            'rcvd_bytes': log.rcvd_bytes or 0,
            'timestamp': log.timestamp
        })
    
    # Fetch Policy Details from DB
    from app.models.policy import Policy
    policy_configs = {}
    
    if unique_policy_ids and device_ids:
        db_policies = g.tenant_session.query(Policy).filter(
            Policy.device_id.in_(device_ids),
            Policy.policy_id.in_(unique_policy_ids)
        ).all()
        
        for p in db_policies:
            policy_configs[str(p.policy_id)] = {
                'name': p.name,
                'vdom': p.vdom,
                'src_intf': p.src_intf,
                'dst_intf': p.dst_intf,
                'src_addr': p.src_addr,
                'dst_addr': p.dst_addr,
                'service': p.service,
                'action': p.action,
                'raw_data': p.raw_data
            }

    # Run local analysis
    analysis = LogAnalyzer.analyze_logs(normalized_logs)
    recommendations = []
    
    # Apply threshold
    if threshold == 'high':
        min_severity = ['critical', 'high']
    elif threshold == 'medium':
        min_severity = ['critical', 'high', 'medium']
    else:
        min_severity = ['critical', 'high', 'medium', 'low', 'info']
    
    for rec in analysis.get('recommendations', []):
        if rec.get('severity', 'info') in min_severity:
            recommendations.append(rec)
    
    # Get API Key for AI analysis
    ai_key = None
    company_id = session.get('company_id')
    if company_id:
        company = db.session.get(Company, company_id)
        if company and company.gemini_api_key:
            ai_key = company.gemini_api_key
    
    if not ai_key:
        ai_key = current_app.config.get('GEMINI_API_KEY')
    
    # Run AI analysis if key available
    if ai_key:
        try:
            # Build prompt based on parameters
            focus_areas = []
            if analyze_denied:
                focus_areas.append('denied/blocked connections')
            if analyze_high_volume:
                focus_areas.append('high volume sessions')
            if analyze_geo:
                focus_areas.append('geographic anomalies')
            if optimize_policies:
                focus_areas.append('policy optimization opportunities')
            if suggest_new_policies:
                focus_areas.append('new policy suggestions')
            
            # Prepare stats for AI
            ai_stats = {k: v for k, v in analysis['stats'].items() 
                       if k not in ['denied_connections', 'high_volume_sessions']}
            
            # Sample data
            sample_logs = []
            if analyze_denied:
                sample_logs.extend(analysis['stats'].get('denied_connections', [])[:20])
            if analyze_high_volume:
                sample_logs.extend(analysis['stats'].get('high_volume_sessions', [])[:10])
            
            # v1.3.0 - Get interface context for AI
            interface_context = []
            vdom_list = set()
            try:
                from app.models.interface import Interface
                if device_ids:
                    interfaces = g.tenant_session.query(Interface).filter(
                        Interface.device_id.in_(list(device_ids))
                    ).all()
                    interface_context = [
                        {'name': i.name, 'role': i.role, 'zone': i.zone, 'ip': i.ip_address}
                        for i in interfaces
                    ]
            except Exception as intf_err:
                # Interface table may not exist in tenant DB yet - rollback failed transaction
                current_app.logger.warning(f"Could not load interface context (table may not exist): {intf_err}")
                try:
                    g.tenant_session.rollback()
                except:
                    pass
            
            try:
                # Get unique VDOMs from logs
                vdom_list = set(log.vdom for log in logs if log.vdom)
            except Exception as e:
                current_app.logger.warning(f"Could not load interface context: {e}")
            
            # Build segmentation context
            segmentation_context = {}
            if filter_vdom:
                segmentation_context['vdom'] = filter_vdom
            if filter_src_intf:
                segmentation_context['src_intf'] = filter_src_intf
            if filter_dst_intf:
                segmentation_context['dst_intf'] = filter_dst_intf
            if filter_device_id:
                segmentation_context['device_id'] = str(filter_device_id)
            
            ai_result = AIService.analyze_security_logs(
                ai_stats, 
                sample_logs, 
                api_key=ai_key,
                focus_areas=focus_areas,
                policies=policy_configs,
                interfaces=interface_context,
                vdoms=list(vdom_list),
                generate_new_policies=suggest_new_policies,
                segmentation=segmentation_context if segmentation_context else None
            )
            
            # Debug logging
            current_app.logger.info(f"AI Analysis complete. Keys in result: {ai_result.keys() if isinstance(ai_result, dict) else 'NOT A DICT'}")
            if isinstance(ai_result, dict):
                current_app.logger.info(f"new_policies in result: {'new_policies' in ai_result}, count: {len(ai_result.get('new_policies', []))}")
                current_app.logger.info(f"recommendations in result: {'recommendations' in ai_result}, count: {len(ai_result.get('recommendations', []))}")
                if ai_result.get('error'):
                    current_app.logger.warning(f"AI returned error: {ai_result.get('error')}")
            
            if 'recommendations' in ai_result:
                for ai_rec in ai_result['recommendations']:
                    rec_severity = ai_rec.get('severity', 'medium')
                    if rec_severity in min_severity:
                        recommendations.append({
                            'category': 'ai_security',
                            'severity': rec_severity,
                            'title': '[AI] ' + ai_rec.get('title', 'Security Insight'),
                            'description': ai_rec.get('description', ''),
                            'recommendation': ai_rec.get('action', ''),
                            'cli_remediation': ai_rec.get('cli_remediation', ''),
                            'related_policy_id': ai_rec.get('related_policy_id'),
                            'affected_interfaces': ai_rec.get('affected_interfaces', []),
                            'affected_count': 0
                        })
            
            # v1.3.0 - Handle new policy suggestions from AI
            new_policies_count = 0
            if 'new_policies' in ai_result and ai_result['new_policies']:
                current_app.logger.info(f"Processing {len(ai_result['new_policies'])} new policies from AI")
                for new_pol in ai_result['new_policies']:
                    service_list = new_pol.get('service', [])
                    if isinstance(service_list, str):
                        service_list = [service_list]
                    recommendations.append({
                        'category': 'ai_new_policy',
                        'severity': 'medium',
                        'title': f"[AI NEW] {new_pol.get('name', 'Suggested Policy')}",
                        'description': new_pol.get('description', 'AI-generated policy based on observed traffic'),
                        'recommendation': f"Create policy: {new_pol.get('src_intf', 'any')} → {new_pol.get('dst_intf', 'any')} [{', '.join(service_list) if service_list else 'ALL'}]",
                        'cli_remediation': new_pol.get('cli_command', ''),
                        'related_policy_id': None,
                        'affected_interfaces': [new_pol.get('src_intf'), new_pol.get('dst_intf')],
                        'affected_count': 0
                    })
                    new_policies_count += 1
            else:
                current_app.logger.info("No new_policies in AI result")
            
            # v1.3.0 - Store traffic flow analysis if present
            traffic_flows = ai_result.get('traffic_flows', [])
            
        except Exception as e:
            import traceback
            current_app.logger.warning(f"AI Analysis failed: {e}")
            current_app.logger.warning(traceback.format_exc())
            traffic_flows = []
            new_policies_count = 0
    
    # Store recommendations in database  
    device_ids = set(log.device_id for log in logs if log.device_id)
    
    try:
        # --- STATIC POLICY ANALYSIS ---
        from app.models.policy import Policy
        policy_vdom_map = {}
        if device_ids:
            # Fetch all policies for these devices
            all_policies = g.tenant_session.query(Policy).filter(Policy.device_id.in_(list(device_ids))).all()
            # Build map for fallback lookup
            policy_vdom_map = {str(p.policy_id): p.vdom for p in all_policies if p.policy_id}
            
            policy_dicts = []
            for p in all_policies:
                # Check status in raw_data if available
                status = 'enable'
                if p.raw_data and isinstance(p.raw_data, dict):
                     status = p.raw_data.get('Status', 'enable')

                policy_dicts.append({
                    'policy_id': str(p.policy_id) if p.policy_id else None,
                    'vdom': p.vdom,
                    'src_addr': str(p.src_addr or ''),
                    'dst_addr': str(p.dst_addr or ''),
                    'service': str(p.service or ''),
                    'action': str(p.action or ''),
                    'status': status
                })
            
            policy_recs = LogAnalyzer.analyze_policies(policy_dicts, stats=analysis.get('stats'))
            recommendations.extend(policy_recs)

        stored_count = 0
        
        for rec in recommendations:
            for device_id in device_ids:
                # Resolve VDOM with fallback
                resolved_vdom = rec.get('related_vdom') or (policy_vdom_map.get(str(rec.get('related_policy_id'))) if rec.get('related_policy_id') else None)
                
                # Prepend VDOM to CLI if present
                cli_cmd = rec.get('cli_remediation')
                if cli_cmd and resolved_vdom and 'config vdom' not in cli_cmd:
                    cli_cmd = f"config vdom\n    edit {resolved_vdom}\n{cli_cmd}"

                recommendation = SecurityRecommendation(
                    device_id=device_id,
                    category=rec.get('category', 'security'),
                    severity=rec.get('severity', 'medium'),
                    title=rec.get('title', 'Security Issue'),
                    description=rec.get('description', ''),
                    recommendation=rec.get('recommendation', ''),
                    related_policy_id=rec.get('related_policy_id'),
                    related_vdom=resolved_vdom,
                    affected_count=rec.get('affected_count', 0),
                    evidence={'source': 'manual_analysis', 'params': data, 'cli_remediation': cli_cmd}
                )
                g.tenant_session.add(recommendation)
                stored_count += 1
        
        g.tenant_session.commit()
    except Exception as e:
        import traceback
        with open("/tmp/issec_error.log", "w") as f:
            traceback.print_exc(file=f)
        g.tenant_session.rollback()
        return jsonify({'error': str(e)}), 500
    
    return jsonify({
        'success': True,
        'logs_analyzed': len(logs),
        'recommendations_count': stored_count,
        'ai_enabled': ai_key is not None
    })


@api_v1_bp.route('/logs/recommendations/<uuid:rec_id>', methods=['PATCH'])
@api_login_required
@api_company_required
@api_product_required('log_analyzer')
def api_update_recommendation(rec_id):
    """
    Update recommendation status
    """
    data = request.get_json()
    status = data.get('status')
    
    if status not in ['open', 'acknowledged', 'resolved', 'ignored']:
        return jsonify({'success': False, 'error': 'Invalid status'}), 400
        
    rec = g.tenant_session.get(SecurityRecommendation, rec_id)
    if not rec:
        return jsonify({'success': False, 'error': 'Recommendation not found'}), 404
        
    rec.status = status
    if status == 'resolved':
        rec.resolved_at = datetime.utcnow()
        rec.resolved_by = g.current_user.email
        
    g.tenant_session.commit()
    
    return jsonify({'success': True})


@api_v1_bp.route('/logs', methods=['DELETE'])
@api_login_required
@api_company_required
@api_product_required('log_analyzer')
def api_delete_logs():
    """
    Delete all logs for the current tenant/device context
    """
    device_id = request.args.get('device_id')
    
    try:
        query = g.tenant_session.query(LogEntry)
        if device_id:
            query = query.filter(LogEntry.device_id == device_id)
            
        deleted_count = query.delete(synchronize_session=False)
        
        # Also clean up import sessions if deleting all or per device
        session_query = g.tenant_session.query(LogImportSession)
        if device_id:
            session_query = session_query.filter(LogImportSession.device_id == device_id)
        session_query.delete(synchronize_session=False)
        
        g.tenant_session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Deleted {deleted_count} logs',
            'deleted_count': deleted_count
        })
    except Exception as e:
        g.tenant_session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_v1_bp.route('/logs/recommendations', methods=['DELETE'])
@api_login_required
@api_company_required
@api_product_required('log_analyzer')
def api_delete_recommendations():
    """
    Delete all security recommendations
    """
    device_id = request.args.get('device_id')
    
    try:
        query = g.tenant_session.query(SecurityRecommendation)
        if device_id:
            query = query.filter(SecurityRecommendation.device_id == device_id)
            
        deleted_count = query.delete(synchronize_session=False)
        g.tenant_session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Deleted {deleted_count} recommendations',
            'deleted_count': deleted_count
        })
    except Exception as e:
        g.tenant_session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
def api_update_recommendation(rec_id):
    """
    Update recommendation status
    
    Request Body (JSON):
        status (str): new status
    
    Returns:
        JSON with updated recommendation
    """
    rec = g.tenant_session.get(SecurityRecommendation, rec_id)
    if not rec:
        return jsonify({'success': False, 'error': 'Recommendation not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'JSON body required'}), 400
    
    new_status = data.get('status')
    if new_status:
        rec.status = new_status
        if new_status == 'resolved':
            rec.resolved_at = datetime.utcnow()
    
    g.tenant_session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Recommendation updated'
    })


@api_v1_bp.route('/logs/import-sessions', methods=['GET'])
@api_login_required
@api_company_required
@api_product_required('log_analyzer')
def api_list_import_sessions():
    """
    List log import sessions
    
    Query Parameters:
        device_id (uuid): Filter by device
    
    Returns:
        JSON with import sessions
    """
    query = g.tenant_session.query(LogImportSession)
    
    device_id = request.args.get('device_id')
    if device_id:
        query = query.filter(LogImportSession.device_id == device_id)
    
    sessions = query.order_by(desc(LogImportSession.imported_at)).all()
    
    data = [{
        'id': str(s.id),
        'device_id': str(s.device_id),
        'filename': s.filename,
        'imported_at': s.imported_at.isoformat() if s.imported_at else None,
        'log_count': s.log_count,
        'start_date': s.start_date.isoformat() if s.start_date else None,
        'end_date': s.end_date.isoformat() if s.end_date else None
    } for s in sessions]
    
    return jsonify({
        'success': True,
        'data': data
    })


def serialize_log(log: LogEntry) -> dict:
    """Serialize a LogEntry to dict"""
    return {
        'id': str(log.id),
        'device_id': str(log.device_id) if log.device_id else None,
        'timestamp': log.timestamp.isoformat() if log.timestamp else None,
        'log_type': log.log_type,
        'subtype': log.subtype,
        'level': log.level,
        'action': log.action,
        'vdom': log.vdom,
        'src_ip': log.src_ip,
        'src_port': log.src_port,
        'src_intf': log.src_intf,
        'src_country': log.src_country,
        'dst_ip': log.dst_ip,
        'dst_port': log.dst_port,
        'dst_intf': log.dst_intf,
        'dst_country': log.dst_country,
        'policy_id': log.policy_id,
        'service': log.service,
        'app': log.app,
        'sent_bytes': log.sent_bytes,
        'rcvd_bytes': log.rcvd_bytes,
        'duration': log.duration
    }


# ============================================================
# Configuration Endpoints
# ============================================================

@api_v1_bp.route('/logs/config', methods=['GET'])
@api_login_required
@api_company_required
@api_product_required('log_analyzer')
def api_get_config():
    """
    Get Log Analyzer configuration status
    
    Returns:
        JSON with config status (has_api_key, etc.)
    """
    from flask import current_app
    from app.models.core import Company
    
    company_id = session.get('company_id')
    has_api_key = False
    api_key_source = None
    
    # Check company-specific key first
    if company_id:
        company = db.session.get(Company, company_id)
        if company and company.gemini_api_key:
            has_api_key = True
            api_key_source = 'company'
    
    # Check global config as fallback
    if not has_api_key and current_app.config.get('GEMINI_API_KEY'):
        has_api_key = True
        api_key_source = 'global'
    
    return jsonify({
        'success': True,
        'has_api_key': has_api_key,
        'api_key_source': api_key_source
    })


@api_v1_bp.route('/logs/config', methods=['POST'])
@api_login_required
@api_company_required
@api_product_required('log_analyzer')
def api_save_config():
    """
    Save Log Analyzer configuration (Gemini API Key)
    
    Request Body (JSON):
        gemini_api_key (str): The Gemini API key to save
    
    Returns:
        JSON with success status
    """
    from app.models.core import Company
    
    data = request.get_json()
    if not data:
        return jsonify({
            'success': False,
            'error': 'Request body must be JSON'
        }), 400
    
    gemini_api_key = data.get('gemini_api_key')
    if not gemini_api_key:
        return jsonify({
            'success': False,
            'error': 'gemini_api_key is required'
        }), 400
    
    company_id = session.get('company_id')
    if not company_id:
        return jsonify({
            'success': False,
            'error': 'Company not selected'
        }), 400
    
    try:
        company = db.session.get(Company, company_id)
        if not company:
            return jsonify({
                'success': False,
                'error': 'Company not found'
            }), 404
        
        company.gemini_api_key = gemini_api_key
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Configuration saved successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_v1_bp.route('/logs/recommendations/export', methods=['POST'])
@api_login_required
@api_company_required
@api_product_required('log_analyzer')
def api_export_recommendations():
    """Export recommendations to CSV or PDF"""
    data = request.get_json() or {}
    export_all = data.get('filters', {}).get('all', False)
    selected_ids = data.get('ids', [])
    filters = data.get('filters', {})
    output_format = data.get('format', 'csv')
    
    query = g.tenant_session.query(SecurityRecommendation)
    
    device_id = filters.get('device_id')
    if export_all:
        if device_id:
            query = query.filter(SecurityRecommendation.device_id == device_id)
    else:
        if not selected_ids:
             return jsonify({'error': 'No recommendations selected'}), 400
        query = query.filter(SecurityRecommendation.id.in_(selected_ids))
        
    recommendations = query.all()
    
    if not recommendations:
        return jsonify({'error': 'No data to export'}), 400

    if output_format == 'pdf':
        buffer = io.BytesIO()
        logo_path = os.path.join(os.getcwd(), 'app', 'static', 'img', 'issec.png')
        
        # Company Info
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
        
        # Determine Device
        device = None
        if device_id:
             device = g.tenant_session.get(Equipo, device_id)
        if not device and recommendations:
             device = recommendations[0].device
             
        if not device:
             # Create dummy device for header if mixed or unknown
             # Or error? Better to handle gracefully.
             class DummyDevice:
                 def __init__(self):
                     self.nombre = "Múltiples Dispositivos / Desconocido"
                     self.site = None
                     self.serial = "N/A"
                     self.hostname = ""
                     self.ha_habilitado = False
             device = DummyDevice()

        filter_info = {
            'Filtros': 'Selección Manual' if selected_ids else 'Todos',
            'Dispositivo': device.nombre
        }
        
        pdf = PDFReportGenerator(buffer, logo_path, company_logo_path, company_name)
        pdf.generate_recommendations(device, recommendations, "Reporte de Recomendaciones AI", filter_info)
        
        buffer.seek(0)
        output = make_response(buffer.getvalue())
        output.headers["Content-Disposition"] = "attachment; filename=recommendations.pdf"
        output.headers["Content-type"] = "application/pdf"
        return output

    # CSV Fallback
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID', 'Severity', 'Device', 'VDOM', 'Policy ID', 'Title', 'Description', 'Recommendation', 'CLI Remediation', 'Status'])
    
    for r in recommendations:
        evidence = r.evidence or {}
        cli = evidence.get('cli_remediation', '')
        device_name = r.device.nombre if r.device else 'Unknown'
        
        cw.writerow([
            str(r.id),
            r.severity,
            device_name,
            r.related_vdom or '',
            str(r.related_policy_id) if r.related_policy_id is not None else '0',
            r.title,
            r.description,
            r.recommendation,
            cli,
            r.status
        ])
        
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=recommendations.csv"
    output.headers["Content-type"] = "text/csv"
    return output
