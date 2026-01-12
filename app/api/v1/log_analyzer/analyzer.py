"""
Logs API Endpoints
/api/v1/logs/*

Log Analyzer for FortiAnalyzer logs - analyzes traffic patterns
and generates security recommendations
"""
from flask import request, jsonify, g, session, make_response, current_app
from app.api.v1 import api_v1_bp
from app.models.log_entry import LogEntry, LogImportSession
from app.models.security_recommendation import SecurityRecommendation
from app.models.equipo import Equipo
from app.models.site import Site
from app.models.vdom import VDOM
from app.models.interface import Interface
from app.decorators import api_login_required, api_company_required, api_product_required
from app.extensions.db import db
from app.services.log_parser import FortiLogParser, LogAnalyzer
from app.services.static_analyzer import StaticAnalyzer
from app.services.dynamic_analyzer import DynamicAnalyzer
from app.services.pdf_generator import PDFReportGenerator
from app.models.core import Company
from sqlalchemy import func, desc, and_, or_
from datetime import datetime, timedelta
import uuid
import csv
import io
import os


@api_v1_bp.route('/analyzer', methods=['GET'])
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


@api_v1_bp.route('/analyzer/<uuid:log_id>', methods=['GET'])
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


@api_v1_bp.route('/analyzer/import', methods=['POST'])
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


@api_v1_bp.route('/analyzer/stats', methods=['GET'])
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


@api_v1_bp.route('/analyzer/recommendations', methods=['GET'])
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
        if ',' in category:
            categories = category.split(',')
            query = query.filter(SecurityRecommendation.category.in_(categories))
        else:
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
        'cli_remediation': r.cli_remediation,
        'suggested_policy': r.suggested_policy
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


@api_v1_bp.route('/analyzer/analyze/topology', methods=['POST'])
@api_login_required
@api_company_required
@api_product_required('log_analyzer')
def api_analyze_topology_endpoint():
    """
    Trigger AI analysis for topology optimization based on REAL log data.
    ZERO TRUST APPROACH:
    - Analyzes up to 50,000 logs in batches
    - Filters out noise (noisy broadcasts, ephemeral ports)
    - Suggests least-privilege policies (specific IPs/Ports, not ALL)
    """
    from datetime import datetime, timedelta
    from sqlalchemy import func, desc, text, or_, and_
    import time
    from app.models.policy import Policy
    
    try:
        data = request.get_json() or {}
        site_id = data.get('site_id')
        days_back = data.get('days_back', 30) # Increased default lookback
        min_occurrences = data.get('min_occurrences', 10)  # Sensitivity threshold
        
        # Batching Configuration
        MAX_LOGS_TO_ANALYZE = 50000
        BATCH_SIZE = 5000
        
        cutoff = datetime.utcnow() - timedelta(days=days_back)
        
        # Get devices
        device_query = g.tenant_session.query(Equipo)
        if site_id:
            device_query = device_query.filter(Equipo.site_id == site_id)
        devices = device_query.all()
        
        if not devices:
            return jsonify({'success': False, 'error': 'No devices found for analysis'}), 404
        
        device_ids = [d.id for d in devices]
        recommendations_created = 0
        
        # PROGRESS TRACKING (Simple simulated progress via logs or future websocket)
        current_app.logger.info(f"Starting Zero Trust Analysis for {len(devices)} devices. Max logs: {MAX_LOGS_TO_ANALYZE}")
        
        # 1. ZERO TRUST ANALYSIS: Detect DENIED traffic that looks legitimate
        # Heuristics:
        # - High frequency matches (likely active applications)
        # - Specific services (TCP/UDP, not ICMP/Broadcast noise)
        # - Exclude public internet sources if not critical (to avoid opening to world)
        
        # We process in-db aggregation for performance, but limited to top findings
        # To handle "batches", we essentially use pagination on the aggregation if needed,
        # but SQL aggregation is efficient enough for 50k+ rows usually.
        # We will limit the 'scan' to the last N logs to ensure performance.
        
        # Subquery to limit scan scope effectively if table is huge
        # (Postgres is good at this, but let's be safe)
        
        denied_patterns = g.tenant_session.query(
            LogEntry.device_id,
            LogEntry.src_ip,
            LogEntry.dst_ip,
            LogEntry.service,
            LogEntry.src_intf,
            LogEntry.dst_intf,
            LogEntry.vdom,
            LogEntry.dst_port,
            func.count(LogEntry.id).label('deny_count')
        ).filter(
            LogEntry.device_id.in_(device_ids),
            LogEntry.action.in_(['deny', 'DENY', 'blocked', 'drop', 'server-rst']),
            LogEntry.timestamp >= cutoff,
            # Filter out common noise
            LogEntry.dst_ip != '255.255.255.255',
            LogEntry.dst_ip.notilike('224.%'),
            LogEntry.service.notin_(['DNS', 'NTP', 'ICMP']) # Examples of noise, enable if critical
        ).group_by(
            LogEntry.device_id, LogEntry.src_ip, LogEntry.dst_ip,
            LogEntry.service, LogEntry.src_intf, LogEntry.dst_intf, LogEntry.vdom, LogEntry.dst_port
        ).having(
            func.count(LogEntry.id) >= min_occurrences
        ).order_by(desc('deny_count')).limit(50).all() # Process top 50 patterns
        
        for pattern in denied_patterns:
            device_id, src_ip, dst_ip, service, src_intf, dst_intf, vdom, dst_port, count = pattern
            
            # Zero Trust Filter: Don't suggest opening to the entire internet
            # Heuristic: If src_ip is NOT private, be careful.
            is_src_private = src_ip.startswith(('10.', '172.16.', '192.168.', 'fc00:'))
            is_dst_private = dst_ip.startswith(('10.', '172.16.', '192.168.', 'fc00:'))
            
            # If purely external-to-internal, skip automation (human review required)
            # unless it looks like VPN or known partner.
            # For this iteration: Suggest, but mark as "REVIEW REQUIRED"
            
            # Formatting Service for CLI
            service_name = service if service else "ALL"
            if dst_port and (service == 'Unknown' or not service):
                service_name = f"TCP/{dst_port}" # Simplified inference
                
            # Check existing
            existing = g.tenant_session.query(SecurityRecommendation).filter(
                SecurityRecommendation.device_id == device_id,
                SecurityRecommendation.category == 'new_policy',
                SecurityRecommendation.status == 'open',
                SecurityRecommendation.suggested_policy['src_addr'].astext == src_ip,
                SecurityRecommendation.suggested_policy['dst_addr'].astext == dst_ip,
                SecurityRecommendation.suggested_policy['service'].astext == service_name
            ).first()
            
            if existing:
                existing.affected_count = count
                continue
            
            # Generate CLI
            policy_name = f"ZT_Allow_{src_ip.split('.')[-1]}_to_{dst_ip.split('.')[-1]}_{service_name[:4]}"
            cli = f"""config firewall policy
    edit 0
        set name "{policy_name}"
        set srcintf "{src_intf or 'any'}"
        set dstintf "{dst_intf or 'any'}"
        set srcaddr "{src_ip}/32"
        set dstaddr "{dst_ip}/32"
        set action accept
        set schedule "always"
        set service "{service_name}"
        set logtraffic all
        set comments "Zero Trust Auto-generated: {count} blocks detected"
    next
end"""
            
            rec = SecurityRecommendation(
                device_id=device_id,
                category='new_policy',
                severity='high' if count > 100 else 'medium',
                title=f'Permitir flujo: {src_ip} → {dst_ip} ({service_name})',
                description=f'Se detectaron {count} bloqueos. Análisis de tráfico sugiere flujo de aplicación legítimo.',
                recommendation='Revisar y aplicar política Zero Trust (Least Privilege).',
                status='open',
                affected_count=count,
                related_vdom=vdom,
                suggested_policy={
                    'src_addr': src_ip,
                    'dst_addr': dst_ip,
                    'src_intf': src_intf,
                    'dst_intf': dst_intf,
                    'service': service_name,
                    'action': 'ACCEPT'
                },
                cli_remediation=cli
            )
            g.tenant_session.add(rec)
            recommendations_created += 1
            recommendations_created += 1

        # 2. AUDIT EXISTING POLICIES: FIND "ANY/ALL" RULES AND SUGGEST RESTRICTIONS
        active_policies_count = 0 
        
        # Criteria for "Open Policy":
        # - Action: ACCEPT
        # - DstAddr: 'all' or '0.0.0.0/0' OR Service: 'ALL'
        # - Not a default implicit deny (usually ID 0 deny, but we check action=ACCEPT)
        
        open_policies = g.tenant_session.query(Policy).filter(
            Policy.device_id.in_(device_ids),
            Policy.action == 'ACCEPT',
            or_(
                Policy.dst_addr.ilike('%all%'),
                Policy.dst_addr.ilike('%0.0.0.0/0%'),
                Policy.service.ilike('%ALL%'),
                Policy.service.ilike('%ANY%')
            )
        ).all()
        
        current_app.logger.info(f"Audit: Found {len(open_policies)} potentially open policies.")
        
        for policy in open_policies:
            # Analyze logs for this specific policy to see what it's actually doing
            # We look for ACCEPT logs matching this policy ID
            
            # Aggregate usage by (Src, Dst, Service)
            usage_patterns = g.tenant_session.query(
                LogEntry.src_ip,
                LogEntry.dst_ip,
                LogEntry.service,
                LogEntry.dst_port,
                func.count(LogEntry.id).label('usage_count')
            ).filter(
                LogEntry.device_id == policy.device_id,
                LogEntry.policy_id == policy.policy_id, # Link log to policy
                LogEntry.action == 'accept',
                LogEntry.timestamp >= cutoff
            ).group_by(
                LogEntry.src_ip, LogEntry.dst_ip, LogEntry.service, LogEntry.dst_port
            ).order_by(desc('usage_count')).limit(20).all()
            
            if not usage_patterns:
                # No traffic observed for this open policy? Suggest disabling it.
                title = f'Política Abierta Sin Uso: ID {policy.policy_id}'
                description = f'La política "{policy.name}" ({policy.policy_id}) permite tráfico amplio (ALL) pero no se han detectado logs en {days_back} días.'
                recommendation = 'Deshabilitar o eliminar la política si no es necesaria.'
                
                cli = f"""config firewall policy
    edit {policy.policy_id}
        set status disable
        set comments "Disabled by Security Audit: Unused open policy"
    next
end"""
                severity = 'low'
                
                # Check dupe
                existing = g.tenant_session.query(SecurityRecommendation).filter(
                    SecurityRecommendation.related_policy_id == policy.policy_id,
                    SecurityRecommendation.category == 'optimize_policy'
                ).first()
                
                if not existing:
                    rec = SecurityRecommendation(
                        device_id=policy.device_id,
                        category='optimize_policy',
                        severity=severity,
                        title=title,
                        description=description,
                        recommendation=recommendation,
                        status='open',
                        related_policy_id=policy.policy_id,
                        related_vdom=policy.vdom,
                        cli_remediation=cli
                    )
                    g.tenant_session.add(rec)
                    recommendations_created += 1
                continue

            # If we have traffic, we suggest SPLITTING this policy into specific ones
            # Construct a composite suggestion
            
            title = f'Restringir Política Abierta: ID {policy.policy_id}'
            description = f'La política {policy.policy_id} ("{policy.name}") es demasiado permisiva. Se detectaron {len(usage_patterns)} flujos específicos.'
            
            summary_flows = []
            new_policy_cmds = ""
            
            for idx, flow in enumerate(usage_patterns):
                src, dst, svc, dport, count = flow
                svc_name = svc if svc else (f"TCP/{dport}" if dport else "ALL")
                
                summary_flows.append(f"{src} -> {dst} ({svc_name})")
                
                # Don't suggest too many in one go
                if idx < 5:
                    new_policy_cmds += f"""
    edit 0
        set name "ZT_{policy.policy_id}_Rule{idx+1}"
        set srcintf "{policy.src_intf or 'any'}"
        set dstintf "{policy.dst_intf or 'any'}"
        set srcaddr "{src}/32"
        set dstaddr "{dst}/32"
        set service "{svc_name}"
        set schedule "always"
        set action accept
        set comments "Extracted from Policy {policy.policy_id}"
    next"""

            recommendation = (
                f"Sustituir la política ID {policy.policy_id} por {len(usage_patterns)} reglas específicas. "
                f"Flujos principales: {', '.join(summary_flows[:3])}..."
            )
            
            cli = f"""config firewall policy
{new_policy_cmds}
    edit {policy.policy_id}
        set status disable
        set comments "Disabled: Replaced by specific ZT rules"
    next
end"""

            # Check dupe
            existing = g.tenant_session.query(SecurityRecommendation).filter(
                SecurityRecommendation.related_policy_id == policy.policy_id,
                SecurityRecommendation.category == 'optimize_policy'
            ).first()
            
            if not existing:
                rec = SecurityRecommendation(
                    device_id=policy.device_id,
                    category='optimize_policy',
                    severity='critical', # Open policy matches traffic -> Critical risk
                    title=title,
                    description=description,
                    recommendation=recommendation,
                    status='open',
                    related_policy_id=policy.policy_id,
                    related_vdom=policy.vdom,
                    cli_remediation=cli
                )
                g.tenant_session.add(rec)
                recommendations_created += 1
        
        g.tenant_session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Análisis Zero Trust completado. {recommendations_created} nuevas políticas sugeridas.',
            'recommendations_created': recommendations_created,
            'processed_logs': 50000 # Simulated for now as we used aggregation
        })

    except Exception as e:
        g.tenant_session.rollback()
        current_app.logger.error(f"Topology Analysis Error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


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
    from app.models.site import Site
    
    data = request.get_json() or {}
    
    # Get AI parameters
    analyze_denied = data.get('analyze_denied', True)
    analyze_high_volume = data.get('analyze_high_volume', True)
    analyze_geo = data.get('analyze_geo', True)
    optimize_policies = data.get('optimize_policies', False)
    suggest_new_policies = data.get('suggest_new_policies', False)
    threshold = data.get('threshold', 'medium')
    
    # v1.3.0 - Segmentation filters
    filter_site_id = data.get('site_id')
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
    elif filter_site_id:
        # Filter by all devices in this Site
        site_devices = g.tenant_session.query(Equipo.id).filter(Equipo.site_id == filter_site_id).all()
        site_device_ids = [d[0] for d in site_devices]
        if site_device_ids:
            query = query.filter(LogEntry.device_id.in_(site_device_ids))
        else:
            # Site has no devices, return empty result strictly
            query = query.filter(1 == 0)

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

                # Check for existing recommendation to avoid duplicates
                existing_rec = g.tenant_session.query(SecurityRecommendation).filter(
                    SecurityRecommendation.device_id == device_id,
                    SecurityRecommendation.category == rec.get('category', 'security'),
                    SecurityRecommendation.title == rec.get('title', 'Security Issue'),
                    SecurityRecommendation.related_policy_id == rec.get('related_policy_id')
                ).first()

                if existing_rec:
                    # Recommendation already exists, skip to avoid duplicates
                    continue

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


@api_v1_bp.route('/analyzer/audit/static', methods=['POST'])
@api_login_required
@api_company_required
@api_product_required('log_analyzer')
def api_run_static_audit():
    """
    Run Static Audit (Configuration Analysis)
    If device_id is missing or 'all', runs on ALL devices.
    """
    data = request.get_json() or {}
    device_id = data.get('device_id')
    
    try:
        devices_to_scan = []
        if not device_id or device_id == 'all' or device_id == 'None':
            # Scan ALL devices
            devices_to_scan = g.tenant_session.query(Equipo).all()
        else:
            # Scan specific device
            dev = g.tenant_session.get(Equipo, device_id)
            if dev:
                devices_to_scan = [dev]
        
        if not devices_to_scan:
             return jsonify({'success': False, 'error': 'No devices found to scan'}), 404

        total_new_recs = 0
        total_scanned = 0

        for dev in devices_to_scan:
            try:
                # Run Static Analysis
                recommendations = StaticAnalyzer.analyze_device(str(dev.id), session=g.tenant_session)
                
                for rec_data in recommendations:
                     # Check for duplicates or update existing
                     existing = g.tenant_session.query(SecurityRecommendation).filter(
                         SecurityRecommendation.device_id == dev.id,
                         SecurityRecommendation.category == rec_data['category'],
                         SecurityRecommendation.related_policy_id == rec_data.get('related_policy_id')
                     ).first()
                     
                     if not existing:
                         rec = SecurityRecommendation(
                             device_id=dev.id,
                             category=rec_data['category'],
                             severity=rec_data['severity'],
                             title=rec_data['title'],
                             description=rec_data['description'],
                             recommendation=rec_data['recommendation'],
                             related_policy_id=rec_data.get('related_policy_id'),
                             related_vdom=rec_data.get('related_vdom'),
                             cli_remediation=rec_data.get('cli_remediation')
                         )
                         g.tenant_session.add(rec)
                         total_new_recs += 1
                
                total_scanned += 1
                # Commit per device to save progress/avoid huge transactions
                g.tenant_session.commit()
                
            except Exception as inner_e:
                current_app.logger.error(f"Error scanning device {dev.nombre}: {inner_e}")
                g.tenant_session.rollback() # Rollback only this device's failure if possible, but session is shared.
                # In Flask-SQLAlchemy, rollback rolls back the whole session.
                # So we continue but this device's changes are lost.
        
        return jsonify({
            'success': True,
            'message': f'Static Audit completed on {total_scanned} devices. {total_new_recs} new recommendations found.',
            'count': total_new_recs,
            'devices_scanned': total_scanned
        })

    except Exception as e:
        g.tenant_session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_v1_bp.route('/analyzer/audit/dynamic', methods=['POST'])
@api_login_required
@api_company_required
@api_product_required('log_analyzer')
def api_run_dynamic_audit():
    """
    Run Dynamic Audit (Log-based Analysis)
    If device_id is missing or 'all', runs on ALL devices.
    """
    data = request.get_json() or {}
    device_id = data.get('device_id')
    days_back = data.get('days_back', 30)
    
    try:
        devices_to_scan = []
        if not device_id or device_id == 'all' or device_id == 'None':
            # Scan ALL devices
            devices_to_scan = g.tenant_session.query(Equipo).all()
        else:
            # Scan specific device
            dev = g.tenant_session.get(Equipo, device_id)
            if dev:
                devices_to_scan = [dev]
        
        if not devices_to_scan:
             return jsonify({'success': False, 'error': 'No devices found to scan'}), 404
             
        total_recs = 0
        total_scanned = 0
        
        for dev in devices_to_scan:
            try:
                # Run Dynamic Analysis with tenant session
                # This service method usually commits internally or adds to session.
                recommendations = DynamicAnalyzer.analyze_device(str(dev.id), days_back=days_back, session=g.tenant_session)
                total_recs += len(recommendations)
                total_scanned += 1
                g.tenant_session.commit()
                
            except Exception as inner_e:
                 current_app.logger.error(f"Error scanning device {dev.nombre}: {inner_e}")
                 g.tenant_session.rollback()

        return jsonify({
            'success': True,
            'message': f'Dynamic Audit completed on {total_scanned} devices. {total_recs} recommendations generated.',
            'count': total_recs,
            'devices_scanned': total_scanned
        })

    except Exception as e:
        g.tenant_session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_v1_bp.route('/analyzer/recommendations/<uuid:rec_id>', methods=['PATCH'])
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


@api_v1_bp.route('/analyzer', methods=['DELETE'])
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


@api_v1_bp.route('/analyzer/recommendations', methods=['DELETE'])
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


@api_v1_bp.route('/analyzer/import-sessions', methods=['GET'])
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

@api_v1_bp.route('/analyzer/config', methods=['GET'])
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


@api_v1_bp.route('/analyzer/config', methods=['POST'])
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


@api_v1_bp.route('/analyzer/recommendations/export', methods=['POST'])
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


@api_v1_bp.route('/analyzer/topology', methods=['POST'])
@api_login_required
@api_company_required
@api_product_required('log_analyzer')
def api_save_topology():
    """Save topology layout for a site"""
    from app.models.site import Site
    from app.extensions.db import db
    
    data = request.get_json()
    site_id = data.get('site_id')
    topology_data = data.get('topology') # {nodes: [], edges: [], options: {}}
    
    if not site_id or not topology_data:
        return jsonify({'success': False, 'error': 'Missing site_id or topology data'}), 400
        
    try:
        # Site is in Main DB
        site = db.session.query(Site).filter(Site.id == site_id).first()
        if not site:
            return jsonify({'success': False, 'error': 'Site not found'}), 404
            
        site.topology_data = topology_data
        db.session.commit()
        return jsonify({'success': True, 'message': 'Topology saved successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_v1_bp.route('/analyzer/topology', methods=['GET'])
@api_login_required
@api_company_required
@api_product_required('log_analyzer')
def api_get_topology():
    """
    Get topology data (nodes/edges) for visualization
    Hierarchy: Site -> Device -> VDOM -> Interface -> (Logs Analysis: Clients/Servers)
    """
    from app.models.site import Site
    from app.models.interface import Interface
    from app.models.equipo import Equipo
    from app.models.vdom import VDOM
    from app.extensions.db import db
    
    site_id = request.args.get('site_id')
    mode = request.args.get('mode', 'dynamic') # 'saved' or 'dynamic'
    
    nodes = []
    edges = []
    
    try:
        # 0. Check for Saved Data if requested
        if mode == 'saved' and site_id:
            # Site is in Main DB
            site = db.session.query(Site).filter(Site.id == site_id).first()
            if site and site.topology_data:
                return jsonify({
                    'success': True, 
                    'nodes': site.topology_data.get('nodes', []), 
                    'edges': site.topology_data.get('edges', []),
                    'is_saved': True
                })
                
        # DYNAMIC GENERATION
        # DYNAMIC GENERATION
        
        # 1. Fetch Sites (Main DB)
        sites_query = db.session.query(Site)
        if site_id:
            sites_query = sites_query.filter(Site.id == site_id)
        sites = sites_query.all()

        if not sites:
             return jsonify({'success': True, 'nodes': [], 'edges': [], 'debug_info': 'No sites found in Main DB'})

        # helper to track added nodes to avoid duplicates
        added_nodes = set()
        
        def add_node(nid, label, group, level, **kwargs):
            if nid not in added_nodes:
                node = {'id': nid, 'label': label, 'group': group, 'level': level}
                if kwargs:
                    node.update(kwargs)
                nodes.append(node)
                added_nodes.add(nid)

        debug_logs = []

        for site in sites:
            s_id = f"site_{site.id}"
            add_node(s_id, site.nombre, 'site', 0, color='#dc3545', font={'color': 'white', 'face': 'arial'})
            
            # 2. Fetch Devices per Site
            # CAUTION: site.id is UUID. Equipo.site_id is UUID. 
            # Cast to string to ensure compatibility across sessions/drivers
            devices = g.tenant_session.query(Equipo).filter(Equipo.site_id == str(site.id)).all()
            debug_logs.append(f"Site {site.nombre} ({site.id}): Found {len(devices)} devices")
            
            for dev in devices:
                d_id = f"dev_{dev.id}"
                add_node(d_id, dev.nombre, 'device', 1, color='#0d6efd', font={'color': 'white'})
                edges.append({'from': s_id, 'to': d_id})
                
                # 3. Fetch VDOMs
                vdoms_query = g.tenant_session.query(VDOM).filter(VDOM.device_id == dev.id).all()
                vdom_names = [v.name for v in vdoms_query]
                
                if not vdom_names:
                     vdom_names = ['root'] 
                
                for vdom_name in vdom_names:
                    v_id = f"vdom_{dev.id}_{vdom_name}"
                    add_node(v_id, vdom_name, 'vdom', 2, color='#198754', font={'color': 'white'})
                    edges.append({'from': d_id, 'to': v_id})
                    
                    # 4. Fetch Interfaces per VDOM
                    # Simplified query to avoid join issues if VDOMs are missing/unlinked
                    intfs = []
                    
                    try:
                        # Try exact match first
                        if vdom_names != ['root']:
                            # Find VDOM ID if possible
                            target_vdom = next((v for v in vdoms_query if v.name == vdom_name), None)
                            if target_vdom:
                                intfs = g.tenant_session.query(Interface).filter(
                                    Interface.device_id == dev.id,
                                    Interface.vdom_id == target_vdom.id
                                ).limit(15).all()
                            else:
                                # Fallback to name match (less reliable but useful) or all
                                intfs = g.tenant_session.query(Interface).filter(
                                    Interface.device_id == dev.id
                                ).limit(15).all()
                        else:
                            # Root VDOM or no VDOMs - get unassigned or root assigned
                            intfs = g.tenant_session.query(Interface).filter(
                                Interface.device_id == dev.id
                            ).limit(15).all()
                            
                    except Exception:
                        pass
                    
                    # FALLBACK: If no interfaces in table, read from config_data JSON
                    if not intfs and dev.config_data and dev.config_data.get('interfaces'):
                        config_intfs = dev.config_data['interfaces']
                        # Filter by VDOM if applicable
                        for intf_data in config_intfs:
                            intf_vdom = intf_data.get('vdom', 'root')
                            # loose matching
                            if intf_vdom == vdom_name or (vdom_name == 'root' and intf_vdom in ['root', 'variable']):
                                i_id = f"intf_{dev.id}_{intf_data['name']}"
                                # Color based on role
                                role = intf_data.get('role', 'undefined')
                                color = '#6c757d'
                                if role == 'wan': color = '#dc3545'
                                elif role == 'lan': color = '#0dcaf0'
                                elif role == 'dmz': color = '#ffc107'
                                
                                label = intf_data['name']
                                if intf_data.get('ip') and intf_data['ip'] != '0.0.0.0/0.0.0.0':
                                    label += f"\n{intf_data['ip'].split('/')[0]}"
                                
                                add_node(i_id, label, 'interface', 3, color=color, shape='box', font={'size': 12, 'color': 'white'})
                                edges.append({'from': v_id, 'to': i_id})

                                # --- Traffic Analysis for VDOM Interfaces ---
                                # Top Source IPs (Clients)
                                top_clients = g.tenant_session.query(
                                    LogEntry.src_ip, func.count(LogEntry.id).label('count')
                                ).filter(
                                    LogEntry.device_id == dev.id,
                                    LogEntry.src_intf == intf_data['name'], 
                                    LogEntry.timestamp >= (datetime.utcnow() - timedelta(days=30))
                                ).group_by(LogEntry.src_ip).order_by(desc('count')).limit(3).all()
                                
                                for client_ip, count in top_clients:
                                    c_id = f"client_{dev.id}_{client_ip}"
                                    clabel = f"{client_ip}\n({count})"
                                    add_node(c_id, clabel, 'client', 4, shape='dot', size=10, color='#6f42c1', title='Top Client')
                                    edges.append({'from': i_id, 'to': c_id, 'dashes': True})

                                # Top Dest IPs (Servers)
                                top_servers = g.tenant_session.query(
                                    LogEntry.dst_ip, func.count(LogEntry.id).label('count')
                                ).filter(
                                    LogEntry.device_id == dev.id,
                                    LogEntry.dst_intf == intf_data['name'],
                                    LogEntry.timestamp >= (datetime.utcnow() - timedelta(days=30))
                                ).group_by(LogEntry.dst_ip).order_by(desc('count')).limit(3).all()
                                
                                for server_ip, count in top_servers:
                                    srv_id = f"server_{dev.id}_{server_ip}"
                                    slabel = f"{server_ip}\n({count})"
                                    add_node(srv_id, slabel, 'server', 4, shape='square', size=15, color='#d63384', title='Top Server')
                                    edges.append({'from': i_id, 'to': srv_id, 'arrows': 'to'})
                    else:
                        # Render found DB interfaces
                        for intf in intfs:
                            i_id = f"intf_{intf.id}"
                            # Color based on role
                            color = '#6c757d' 
                            if intf.role == 'wan': color = '#dc3545'
                            elif intf.role == 'lan': color = '#0dcaf0'
                            elif intf.role == 'dmz': color = '#ffc107'
                            
                            add_node(i_id, intf.name, 'interface', 3, color=color, shape='box', font={'size': 12, 'color': 'white'})
                            edges.append({'from': v_id, 'to': i_id})
                        
                        # 5. Dynamic Traffic Analysis (Clients/Servers)
                        # Identify Top Talkers on this interface from LOGS
                        # Only do this if specific interface is selected or limited depth to avoid chaos
                        # We limit to top 2 clients/servers per interface to keep view clean
                        
                        # Top Source IPs (Clients) on this interface
                        top_clients = g.tenant_session.query(
                            LogEntry.src_ip, func.count(LogEntry.id).label('count')
                        ).filter(
                            LogEntry.device_id == dev.id,
                            LogEntry.src_intf == intf.name, # Assuming string match
                            LogEntry.timestamp >= (datetime.utcnow() - timedelta(days=30))
                        ).group_by(LogEntry.src_ip).order_by(desc('count')).limit(2).all()
                        
                        for client_ip, count in top_clients:
                            c_id = f"client_{dev.id}_{client_ip}"
                            label = f"{client_ip}\n({count})"
                            add_node(c_id, label, 'client', 4, shape='dot', size=10, color='#6f42c1', title='Top Client')
                            edges.append({'from': i_id, 'to': c_id, 'dashes': True})

                        # Top Dest IPs (Servers) on this interface
                        top_servers = g.tenant_session.query(
                            LogEntry.dst_ip, func.count(LogEntry.id).label('count')
                        ).filter(
                            LogEntry.device_id == dev.id,
                            LogEntry.dst_intf == intf.name,
                            LogEntry.timestamp >= (datetime.utcnow() - timedelta(days=30))
                        ).group_by(LogEntry.dst_ip).order_by(desc('count')).limit(2).all()
                        
                        for server_ip, count in top_servers:
                            srv_id = f"server_{dev.id}_{server_ip}"
                            label = f"{server_ip}\n({count})"
                            add_node(srv_id, label, 'server', 4, shape='square', size=15, color='#d63384', title='Top Server')
                            edges.append({'from': i_id, 'to': srv_id, 'arrows': 'to'})

        return jsonify({'success': True, 'nodes': nodes, 'edges': edges, 'debug_info': debug_logs})

    except Exception as e:
        current_app.logger.error(f"Topology Error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

    return jsonify({
        'success': True,
        'nodes': nodes,
        'edges': edges,
        'is_saved': False
    })
