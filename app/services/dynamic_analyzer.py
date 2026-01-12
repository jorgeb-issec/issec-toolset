from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy import func, and_
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
        policies = session.query(Policy).filter_by(
            device_id=device_id, 
            status='enable'
        ).all()
        
        # Get IDs of policies that HAVE logs
        active_policy_ids = session.query(LogEntry.policy_id).filter(
            LogEntry.device_id == device_id,
            LogEntry.timestamp >= cutoff_date
        ).distinct().all()
        
        active_ids = {str(r[0]) for r in active_policy_ids if r[0] is not None}
        
        recommendations = []
        for p in policies:
            if str(p.policy_id) not in active_ids:
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
        Find specific traffic patterns in permissive policies to suggest constraints.
        """
        session = session or db.session
        cutoff_date = datetime.utcnow() - timedelta(days=days_back)
        recommendations = []
        
        permissive_policies = session.query(Policy).filter(
            Policy.device_id == device_id,
            Policy.status == 'enable',
            Policy.action == 'accept',
            func.lower(Policy.service).contains('all')
        ).all()
        
        for p in permissive_policies:
            used_services = session.query(LogEntry.service, func.count(LogEntry.id)).filter(
                LogEntry.device_id == device_id,
                LogEntry.policy_id == int(p.policy_id),
                LogEntry.timestamp >= cutoff_date
            ).group_by(LogEntry.service).all()
            
            if not used_services:
                continue 
                
            unique_services = [s[0] for s in used_services if s[0]]
            
            if len(unique_services) <= 5: 
                svc_str = " ".join([f'"{s}"' for s in unique_services])
                
                cli = f"""config firewall policy
    edit {p.policy_id}
    set service {svc_str}
    set comments "OPTIMIZED: Restricted services based on logs"
    next
end"""
                rec = DynamicAnalyzer._create_recommendation(
                    device_id=device_id,
                    category='security',
                    severity='medium',
                    title=f'Política {p.policy_id} con permisos excesivos (Servicio ALL)',
                    description=f'La política permite "ALL" pero solo se ha detectado tráfico de: {", ".join(unique_services)}.',
                    recommendation='Restringir la política para permitir solo los servicios utilizados.',
                    related_policy_id=int(p.policy_id),
                    related_vdom=p.vdom,
                    cli_remediation=cli,
                    evidence={'distinct_services': unique_services}
                )
                recommendations.append(rec)

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
