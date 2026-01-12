from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy import func, and_, or_
from app.extensions.db import db
from app.models.policy import Policy
from app.models.log_entry import LogEntry
from app.models.policy_mappings import PolicyServiceMapping
from app.models.security_recommendation import SecurityRecommendation

class DynamicAnalyzer:
    """
    Dynamic Analysis Service for FortiGate Logs.
    Correlates Policy configuration with Log data to find optimization opportunities.
    """

    @staticmethod
    def analyze_device(device_id, days_back=30, session=None) -> List[SecurityRecommendation]:
        """
        Run full dynamic analysis for a device.
        """
        import uuid as uuid_module
        # Ensure device_id is a proper UUID object for SQLAlchemy comparison
        if isinstance(device_id, str):
            device_id = uuid_module.UUID(device_id)
        
        session = session or db.session
        recommendations = []
        
        # 1. Zombie Policies (Unused)
        zombies = DynamicAnalyzer.detect_zombies(device_id, days_back, session)
        recommendations.extend(zombies)
        
        # 2. Least Privilege (Permissive vs Actual)
        least_priv = DynamicAnalyzer.analyze_least_privilege(device_id, days_back, session)
        recommendations.extend(least_priv)
        
        # 3. Noisy Drops (Blocked Traffic)
        noisy_drops = DynamicAnalyzer.analyze_noisy_drops(device_id, days_back, session)
        recommendations.extend(noisy_drops)
        
        # Persist to DB
        for rec in recommendations:
            session.add(rec)
            
        session.commit()
        return recommendations

    @staticmethod
    def analyze_noisy_drops(device_id, days_back=30, session=None) -> List[SecurityRecommendation]:
        """
        Identify high-volume denied traffic patterns.
        """
        session = session or db.session
        cutoff_date = datetime.utcnow() - timedelta(days=days_back)
        recommendations = []
        
        # Query for Top Denies
        top_denies = session.query(
            LogEntry.src_ip,
            LogEntry.dst_ip,
            LogEntry.service,
            LogEntry.dst_port,
            func.count(LogEntry.id).label('count')
        ).filter(
            LogEntry.device_id == device_id,
            LogEntry.action == 'deny',
            LogEntry.timestamp >= cutoff_date
        ).group_by(
            LogEntry.src_ip,
            LogEntry.dst_ip,
            LogEntry.service,
            LogEntry.dst_port
        ).having(func.count(LogEntry.id) > 100).order_by(func.count(LogEntry.id).desc()).limit(10).all()
        
        for row in top_denies:
            src_ip, dst_ip, service, dst_port, count = row
            
            svc_label = service if service else f"TCP/{dst_port}"
            
            rec = DynamicAnalyzer._create_recommendation(
                device_id=device_id,
                category='traffic',
                severity='low', 
                title=f'Tráfico Bloqueado Frecuente: {src_ip} -> {dst_ip} ({svc_label})',
                description=f'Se detectaron {count} bloqueos desde {src_ip} hacia {dst_ip} en el puerto {svc_label}.',
                recommendation='Verificar si este tráfico es legítimo y requiere una política de acceso, o si es un intento de acceso no autorizado.',
                affected_count=count,
                evidence={'src_ip': src_ip, 'dst_ip': dst_ip, 'service': svc_label, 'count': count}
            )
            recommendations.append(rec)
            
        return recommendations

    @staticmethod
    def detect_zombies(device_id, days_back=30, session=None) -> List[SecurityRecommendation]:
        """
        Identify policies that have 0 traffic logs in the analysis period.
        """
        session = session or db.session
        cutoff_date = datetime.utcnow() - timedelta(days=days_back)
        
        # Get all enabled policies
        policies = session.query(Policy).filter(
            Policy.device_id == device_id, 
            func.lower(Policy.status) == 'enable'
        ).all()
        
        # Get IDs of policies that HAVE logs
        active_policy_ids = session.query(LogEntry.policy_id).filter(
            LogEntry.device_id == device_id,
            LogEntry.timestamp >= cutoff_date
        ).distinct().all()
        
        active_ids = {str(r[0]) for r in active_policy_ids if r[0] is not None}
        
        zombie_policies = []
        for p in policies:
            if str(p.policy_id) not in active_ids:
                zombie_policies.append(p)

        recommendations = []
        
        # If too many zombies, summarize them
        if len(zombie_policies) > 10:
            examples = ", ".join([f"{p.policy_id} ({p.name})" for p in zombie_policies[:5]])
            
            # Construct a bulk CLI script for remediating ALL of them (or top 50 to avoid massive text)
            bulk_cli = "config firewall policy\n"
            for p in zombie_policies[:50]:
                 bulk_cli += f"    edit {p.policy_id}\n        set status disable\n        set comments \"DISABLED - Unused for {days_back} days\"\n    next\n"
            bulk_cli += "end"
            
            if len(zombie_policies) > 50:
                 bulk_cli += f"\n# ... and {len(zombie_policies) - 50} more policies."

            rec = DynamicAnalyzer._create_recommendation(
                device_id=device_id,
                category='optimization',
                severity='low',
                title=f'Alto número de Políticas Zombie Detectadas ({len(zombie_policies)})',
                description=f'Se han detectado {len(zombie_policies)} políticas habilitadas sin tráfico en los últimos {days_back} días. Ejemplos: {examples}...',
                recommendation='Revisar masivamente y deshabilitar las políticas no utilizadas para mejorar el rendimiento y seguridad.',
                related_policy_id=None,
                related_vdom=zombie_policies[0].vdom if zombie_policies else None,
                cli_remediation=bulk_cli,
                affected_count=len(zombie_policies)
            )
            recommendations.append(rec)
        else:
            # Individual recommendations for small numbers
            for p in zombie_policies:
                rec = DynamicAnalyzer._create_recommendation(
                    device_id=device_id,
                    category='optimization',
                    severity='low',
                    title=f'Política Zombie Detectada: {p.policy_id}',
                    description=f'La política {p.policy_id} ("{p.name}") no ha registrado tráfico en los últimos {days_back} días.',
                    recommendation='Considerar deshabilitar o eliminar esta política si no es necesaria.',
                    related_policy_id=int(p.policy_id) if p.policy_id.isdigit() else None,
                    related_vdom=p.vdom,
                    cli_remediation=f'config firewall policy\n    edit {p.policy_id}\n    set status disable\n    set comments "DISABLED - Unused for {days_back} days"\n    next\nend'
                )
                recommendations.append(rec)
                
        return recommendations

    @staticmethod
    def analyze_least_privilege(device_id, days_back=30, session=None) -> List[SecurityRecommendation]:
        """
        Analyze fully open ANY/ANY policies and suggest granular ZTNA rules based on logs.
        """
        session = session or db.session
        cutoff_date = datetime.utcnow() - timedelta(days=days_back)
        recommendations = []
        
        # Criteria for "Open Policy":
        # - Action: ACCEPT
        # - SrcAddr/DstAddr: 'all' or '0.0.0.0/0' OR Service: 'ALL'
        # - Not a default implicit deny (usually ID 0 deny, but we check action=ACCEPT)
        
        open_policies = session.query(Policy).filter(
            Policy.device_id == device_id,
            # using lower() for case-insensitive match
            func.lower(Policy.action) == 'accept',
            or_(
                func.lower(Policy.src_addr).contains('all'),
                func.lower(Policy.src_addr).contains('0.0.0.0/0'),
                func.lower(Policy.dst_addr).contains('all'),
                func.lower(Policy.dst_addr).contains('0.0.0.0/0'),
                func.lower(Policy.service).contains('all'),
                func.lower(Policy.service).contains('any')
            )
        ).all()
        
        active_ztna_count = 0
        MAX_DETAILED_ZTNA = 20
        recs_buffer = []

        for policy in open_policies:
            # Skip if disabled (though query checked action=accept, status might be separate)
            if policy.status and policy.status.lower() == 'disable':
                continue

            # Analyze logs for this specific policy to see what it's actually doing
            # Aggregate usage by (Src, Dst, Service)
            usage_patterns = session.query(
                LogEntry.src_ip,
                LogEntry.dst_ip,
                LogEntry.service,
                LogEntry.dst_port,
                func.count(LogEntry.id).label('usage_count')
            ).filter(
                LogEntry.device_id == policy.device_id,
                LogEntry.policy_id == int(policy.policy_id) if policy.policy_id.isdigit() else 0, 
                # Handle potential type mismatch if policy_id is str in one and int in other
                func.lower(LogEntry.action) == 'accept',
                LogEntry.timestamp >= cutoff_date
            ).group_by(
                LogEntry.src_ip, LogEntry.dst_ip, LogEntry.service, LogEntry.dst_port
            ).order_by(func.count(LogEntry.id).desc()).limit(20).all()
            
            pid = policy.policy_id
            pname = policy.name or "Unnamed"
            
            if not usage_patterns:
                # No traffic observed for this open policy? Suggest disabling it.
                # (Existing Zombie Logic - kept as is)
                title = f'Política Abierta Sin Uso: ID {pid}'
                description = f'La política "{pname}" ({pid}) permite tráfico amplio (ALL) pero no se han detectado logs en {days_back} días.'
                recommendation = 'Deshabilitar o eliminar la política si no es necesaria.'
                
                cli = f"""config firewall policy
    edit {pid}
        set status disable
        set comments "Disabled by Security Audit: Unused open policy"
    next
end"""
                severity = 'low'
                
                rec = DynamicAnalyzer._create_recommendation(
                    device_id=device_id,
                    category='optimization',
                    severity=severity,
                    title=title,
                    description=description,
                    recommendation=recommendation,
                    related_policy_id=int(pid) if pid.isdigit() else None,
                    related_vdom=policy.vdom,
                    cli_remediation=cli
                )
                recommendations.append(rec)
                continue

            # If we have traffic, we suggest SPLITTING this policy into specific ones
            
            # --- SUMMARIZATION CHECK ---
            if active_ztna_count >= MAX_DETAILED_ZTNA:
                 # Already hit limit, don't generate more detailed ones.
                 # We will add a summary recommendation later if needed.
                 recs_buffer.append(policy)
                 continue
            
            active_ztna_count += 1
            
            # Construct a composite suggestion
            title = f'Recomendación ZTNA: Restringir Política {pid}'
            description = f'La política {pid} es demasiado permisiva (ALL). Se detectaron {len(usage_patterns)} flujos específicos reales.'
            
            summary_flows = []
            new_policy_cmds = ""
            
            for idx, flow in enumerate(usage_patterns):
                src, dst, svc, dport, count = flow
                svc_name = svc if svc else (f"TCP/{dport}" if dport else "ALL")
                
                summary_flows.append(f"{src} -> {dst} ({svc_name})")
                
                # Create granular policy command
                if idx < 5:
                    new_policy_cmds += f"""
    edit 0
        set name "ZT_{pid}_Rule{idx+1}"
        set srcintf "{policy.src_intf or 'any'}"
        set dstintf "{policy.dst_intf or 'any'}"
        set srcaddr "{src}/32"
        set dstaddr "{dst}/32"
        set service "{svc_name}"
        set schedule "always"
        set action accept
        set comments "Extracted from Policy {pid}"
    next"""

            recommendation_text = (
                f"Sustituir la política ID {pid} por reglas específicas basadas en el tráfico real. "
                f"Flujos principales detectados: {', '.join(summary_flows[:3])}..."
            )
            
            cli = f"""config firewall policy
{new_policy_cmds}
    edit {pid}
        set status disable
        set comments "Disabled: Replaced by specific ZT rules"
    next
end"""

            rec = DynamicAnalyzer._create_recommendation(
                device_id=device_id,
                category='security', # Changed to security as it's a risk
                severity='high',     # User requested levels: High
                title=title,
                description=description,
                recommendation=recommendation_text,
                related_policy_id=int(pid) if pid.isdigit() else None,
                related_vdom=policy.vdom,
                cli_remediation=cli,
                evidence={'flow_count': len(usage_patterns), 'top_flows': summary_flows}
            )
            recommendations.append(rec)

        # If we have overflowing recommendations, add a Summary
        if recs_buffer:
             count_hidden = len(recs_buffer)
             examples = ", ".join([str(p.policy_id) for p in recs_buffer[:5]])
             recommendations.append(DynamicAnalyzer._create_recommendation(
                 device_id=device_id,
                 category='security',
                 severity='critical',
                 title=f'Revisión Masiva de Políticas Abiertas ({count_hidden} adicionales)',
                 description=f'Se han detectado otras {count_hidden} políticas abiertas con tráfico activo que requieren atención inmediata.',
                 recommendation=f'Revisar las políticas: {examples}... Utilizar este analista por partes o vía CLI.',
                 evidence={'policies': [p.policy_id for p in recs_buffer]}
             ))

        return recommendations

    @staticmethod
    def _create_recommendation(device_id, **kwargs) -> SecurityRecommendation:
        return SecurityRecommendation(
            id=None, 
            device_id=device_id,
            status='open',
            created_at=datetime.utcnow(),
            **kwargs
        )
