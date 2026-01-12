"""
VDOM Analyzer Service
Phase 3: Multi-VDOM Correlation Analysis

Detects:
- VDOM Leaks: Traffic between VDOMs without explicit policies
- Shadow Policies: Duplicate policies across multiple VDOMs
- Orphan Interfaces: Interfaces not referenced by any policy
"""
from datetime import datetime
from typing import List, Dict, Any
from sqlalchemy import func, and_, or_
from app.extensions.db import db
from app.models.policy import Policy
from app.models.vdom import VDOM
from app.models.interface import Interface
from app.models.security_recommendation import SecurityRecommendation


class VDOMAnalyzer:
    """
    Multi-VDOM Correlation Analyzer.
    Identifies cross-VDOM security issues and configuration inconsistencies.
    """

    @staticmethod
    def analyze_device(device_id, session=None) -> List[SecurityRecommendation]:
        """
        Run full VDOM correlation analysis for a device.
        """
        import uuid as uuid_module
        if isinstance(device_id, str):
            device_id = uuid_module.UUID(device_id)
        
        session = session or db.session
        recommendations = []
        
        # 1. Shadow Policies (duplicates across VDOMs)
        shadows = VDOMAnalyzer.detect_shadow_policies(device_id, session)
        recommendations.extend(shadows)
        
        # 2. Orphan Interfaces
        orphans = VDOMAnalyzer.detect_orphan_interfaces(device_id, session)
        recommendations.extend(orphans)
        
        # 3. VDOM Leak Detection (requires inter-VDOM link analysis)
        leaks = VDOMAnalyzer.detect_vdom_leaks(device_id, session)
        recommendations.extend(leaks)
        
        return recommendations

    @staticmethod
    def detect_shadow_policies(device_id, session=None) -> List[SecurityRecommendation]:
        """
        Detect policies with identical rules across different VDOMs.
        Shadow policies indicate potential misconfiguration or redundancy.
        """
        session = session or db.session
        recommendations = []
        
        # Get all enabled policies for this device
        policies = session.query(Policy).filter(
            Policy.device_id == device_id,
            func.lower(Policy.status) == 'enable'
        ).all()
        
        # Group policies by their "signature" (src, dst, service, action)
        signatures = {}
        for p in policies:
            sig = (
                (p.src_addr or '').lower().strip(),
                (p.dst_addr or '').lower().strip(),
                (p.service or '').lower().strip(),
                (p.action or '').lower().strip()
            )
            if sig not in signatures:
                signatures[sig] = []
            signatures[sig].append(p)
        
        # Find duplicates (same signature, different VDOMs)
        for sig, policy_list in signatures.items():
            if len(policy_list) < 2:
                continue
            
            # Check if they span multiple VDOMs
            vdoms = set(p.vdom for p in policy_list)
            if len(vdoms) < 2:
                continue  # Same VDOM duplicates are handled elsewhere
            
            # This is a shadow policy situation
            policy_ids = [p.policy_id for p in policy_list]
            vdom_names = ", ".join(vdoms)
            
            rec = VDOMAnalyzer._create_recommendation(
                device_id=device_id,
                category='vdom_audit',
                severity='high',
                title=f'Política Duplicada en Múltiples VDOMs',
                description=f'La política con regla ({sig[0]} -> {sig[1]}, Svc: {sig[2]}) existe en {len(vdoms)} VDOMs diferentes: {vdom_names}.',
                recommendation='Consolidar en una única política o verificar si la duplicación es intencional.',
                evidence={
                    'policy_ids': policy_ids,
                    'vdoms': list(vdoms),
                    'signature': sig
                }
            )
            recommendations.append(rec)
        
        return recommendations

    @staticmethod
    def detect_orphan_interfaces(device_id, session=None) -> List[SecurityRecommendation]:
        """
        Detect interfaces not referenced by any policy.
        Orphan interfaces may indicate unused resources or misconfiguration.
        """
        session = session or db.session
        recommendations = []
        
        # Get all interfaces for this device
        interfaces = session.query(Interface).filter_by(device_id=device_id).all()
        
        # Get all unique interface names used in policies (src or dst)
        policies = session.query(Policy).filter_by(device_id=device_id).all()
        
        used_interfaces = set()
        for p in policies:
            if p.src_intf:
                used_interfaces.add(p.src_intf.lower().strip())
            if p.dst_intf:
                used_interfaces.add(p.dst_intf.lower().strip())
        
        # Find orphans
        orphan_list = []
        for intf in interfaces:
            if intf.name and intf.name.lower().strip() not in used_interfaces:
                # Exclude system interfaces (loopback, management, etc.)
                if intf.name.lower() not in ('loopback', 'mgmt', 'ha', 'ssl.root', 'any'):
                    orphan_list.append(intf)
        
        if orphan_list:
            if len(orphan_list) > 5:
                # Summarize
                names = ", ".join([i.name for i in orphan_list[:5]]) + f"... (+{len(orphan_list)-5} más)"
                rec = VDOMAnalyzer._create_recommendation(
                    device_id=device_id,
                    category='vdom_audit',
                    severity='medium',
                    title=f'Múltiples Interfaces Huérfanas ({len(orphan_list)})',
                    description=f'Se detectaron {len(orphan_list)} interfaces sin políticas asociadas: {names}',
                    recommendation='Verificar si estas interfaces están activas. Considerar eliminar o crear políticas.',
                    evidence={'interfaces': [i.name for i in orphan_list]}
                )
                recommendations.append(rec)
            else:
                # Individual recommendations
                for intf in orphan_list:
                    rec = VDOMAnalyzer._create_recommendation(
                        device_id=device_id,
                        category='vdom_audit',
                        severity='low',
                        title=f'Interfaz Huérfana: {intf.name}',
                        description=f'La interfaz "{intf.name}" no está referenciada por ninguna política.',
                        recommendation='Verificar uso de la interfaz. Crear política o eliminar si no es necesaria.',
                        related_vdom=intf.vdom.name if hasattr(intf, 'vdom') and intf.vdom else None
                    )
                    recommendations.append(rec)
        
        return recommendations

    @staticmethod
    def detect_vdom_leaks(device_id, session=None) -> List[SecurityRecommendation]:
        """
        Detect potential inter-VDOM traffic without explicit policies.
        This requires analyzing VDOM-link interfaces and their associated policies.
        """
        session = session or db.session
        recommendations = []
        
        # Get VDOMs for this device
        vdoms = session.query(VDOM).filter_by(device_id=device_id).all()
        
        if len(vdoms) < 2:
            return []  # No multi-VDOM scenario
        
        # Look for inter-VDOM link interfaces (usually named like "vdom-link" or NPU-vlink)
        # These are often configured as src/dst in policies that allow inter-VDOM traffic
        link_interfaces = session.query(Interface).filter(
            Interface.device_id == device_id,
            or_(
                func.lower(Interface.name).contains('vdom'),
                func.lower(Interface.name).contains('npu'),
                func.lower(Interface.name).contains('vlink')
            )
        ).all()
        
        if not link_interfaces:
            # No explicit VDOM-link interfaces found - this is OK for separate VDOMs
            return []
        
        # Check if there are policies using these link interfaces
        link_names = [i.name.lower() for i in link_interfaces]
        
        policies_using_links = session.query(Policy).filter(
            Policy.device_id == device_id,
            or_(
                func.lower(Policy.src_intf).in_(link_names),
                func.lower(Policy.dst_intf).in_(link_names)
            )
        ).all()
        
        if not policies_using_links:
            # VDOM links exist but no policies - potential leak or misconfiguration
            rec = VDOMAnalyzer._create_recommendation(
                device_id=device_id,
                category='vdom_audit',
                severity='critical',
                title='Posible Fuga Inter-VDOM Detectada',
                description=f'Se detectaron interfaces de enlace VDOM ({", ".join(link_names)}) pero sin políticas de control asociadas.',
                recommendation='Verificar configuración de inter-VDOM routing. Crear políticas explícitas para controlar el tráfico.',
                evidence={'link_interfaces': link_names}
            )
            recommendations.append(rec)
        else:
            # Check if policies are too permissive
            for p in policies_using_links:
                if p.src_addr and 'all' in p.src_addr.lower() and p.dst_addr and 'all' in p.dst_addr.lower():
                    rec = VDOMAnalyzer._create_recommendation(
                        device_id=device_id,
                        category='vdom_audit',
                        severity='high',
                        title=f'Política Inter-VDOM Permisiva: {p.policy_id}',
                        description=f'La política {p.policy_id} permite tráfico ANY/ANY entre VDOMs.',
                        recommendation='Restringir el tráfico inter-VDOM a flujos específicos.',
                        related_policy_id=int(p.policy_id) if p.policy_id.isdigit() else None,
                        related_vdom=p.vdom
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
