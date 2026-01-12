import logging
from typing import List, Dict, Any, Optional
from app.extensions.db import db
from app.models.policy import Policy
from app.models.policy_mappings import PolicyInterfaceMapping, PolicyAddressMapping, PolicyServiceMapping

class StaticAnalyzer:
    """
    Static Analysis Service for FortiGate Configurations.
    Performs audits without needing traffic logs, based on Best Practices.
    """

    @staticmethod
    def analyze_device(device_id, session=None) -> List[Dict[str, Any]]:
        """
        Analyze all policies for a given device stored in the database.
        """
        import uuid as uuid_module
        if isinstance(device_id, str):
            device_id = uuid_module.UUID(device_id)
        
        if not session:
            session = db.session
            
        policies = session.query(Policy).filter_by(device_id=device_id).all()
        
        # Convert DB objects to dict format expected by analyzer
        policy_dicts = []
        for p in policies:
            policy_dicts.append(StaticAnalyzer._policy_to_dict(p, session))
            
        return StaticAnalyzer.analyze_policies(policy_dicts)

    @staticmethod
    def _policy_to_dict(policy: Policy, session=None) -> Dict[str, Any]:
        """
        Convert Policy DB object to dictionary with resolved names
        """
        # Fetch Mappings (with graceful fallback if tables don't exist)
        src_intfs = []
        dst_intfs = []
        src_addrs = []
        dst_addrs = []
        services = []
        
        try:
            # Try to use interface mappings if table exists
            src_intfs = [m.interface.name for m in policy.interface_mappings.filter_by(direction='src').all()]
            dst_intfs = [m.interface.name for m in policy.interface_mappings.filter_by(direction='dst').all()]
        except Exception as e:
            # Table doesn't exist yet - rollback the failed transaction
            if session:
                session.rollback()
            pass
        
        try:
            # Try to use address mappings if table exists
            src_addrs = [m.address.name for m in policy.address_mappings.filter_by(direction='src').all()]
            dst_addrs = [m.address.name for m in policy.address_mappings.filter_by(direction='dst').all()]
        except Exception as e:
            # Table doesn't exist yet - rollback the failed transaction
            if session:
                session.rollback()
            pass
        
        try:
            # Try to use service mappings if table exists
            services = [m.service.name for m in policy.service_mappings.all()]
        except Exception as e:
            # Table doesn't exist yet - rollback the failed transaction
            if session:
                session.rollback()
            pass
        
        # Fallback to text fields if mappings are empty (legacy or table missing)
        if not src_intfs and policy.src_intf:
            src_intfs = [policy.src_intf]
        if not dst_intfs and policy.dst_intf:
            dst_intfs = [policy.dst_intf]
        if not src_addrs and policy.src_addr:
            src_addrs = [policy.src_addr]
        if not dst_addrs and policy.dst_addr:
            dst_addrs = [policy.dst_addr]
        if not services and policy.service:
            services = [policy.service]
        
        return {
            'policy_id': policy.policy_id,
            'id': policy.policy_id,
            'name': policy.name,
            'action': policy.action,
            'status': policy.status,
            'vdom': policy.vdom,
            'srcintf': src_intfs,
            'dstintf': dst_intfs,
            'srcaddr': src_addrs,
            'dstaddr': dst_addrs,
            'service': services
        }

    
    @staticmethod
    def analyze_policies(policies: List[Dict[str, Any]], stats: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Analyze policy configurations for ZTNA best practices.
        
        Args:
            policies: List of policy dictionaries (from ConfigParser or DB objects converted to dicts)
            stats: Optional statistics from LogAnalyzer for context (e.g. usage)
            
        Returns:
            List of recommendations (violations found)
        """
        recommendations = []
        
        for p in policies:
            pid = p.get('id') or p.get('policy_id')
            if not pid: continue
            
            # Helper to handle list or string fields
            def get_field_as_list(field):
                val = p.get(field, [])
                if isinstance(val, str):
                    return [val]
                return val

            src_list = get_field_as_list('srcaddr')
            dst_list = get_field_as_list('dstaddr')
            svc_list = get_field_as_list('service')
            intf_src = get_field_as_list('srcintf')
            intf_dst = get_field_as_list('dstintf')
            
            action = str(p.get('action', '')).lower()
            status = str(p.get('status', 'enable')).lower()
            
            if status == 'disable':
                continue
            
            # Helper: Check for Wildcards
            def has_wildcard(values: List[str]) -> bool:
                for v in values:
                    val = str(v).lower().strip()
                    if val in ('all', 'any', '0.0.0.0/0', '0.0.0.0 0.0.0.0', 'all_icmp'):
                        return True
                return False
            
            is_any_src = has_wildcard(src_list)
            is_any_dst = has_wildcard(dst_list)
            is_any_svc = has_wildcard(svc_list) or 'always' in [str(s).lower() for s in svc_list]
            is_any_src_intf = has_wildcard(intf_src)
            is_any_dst_intf = has_wildcard(intf_dst)
            
            is_accept = 'accept' in action
            
            # --- Checks ---
            
            # 1. Critical: Any/Any/Any Accept
            if is_any_src and is_any_dst and is_any_svc and is_accept:
                recommendations.append({
                    'category': 'security_audit',
                    'severity': 'critical',
                    'title': f'Política {pid} Completamente Abierta (Any/Any/ALL)',
                    'description': f'La política {pid} permite TODO el tráfico (Origen: all, Destino: all, Servicio: ALL).',
                    'recommendation': 'Restringir origen, destino y servicios.',
                    'related_policy_id': pid,
                    'related_vdom': p.get('vdom'),
                    'cli_remediation': StaticAnalyzer._generate_remediation_cli(pid, p)
                })

            # 2. High: Open Source + Open Service
            elif is_any_src and is_any_svc and is_accept:
                recommendations.append({
                    'category': 'security_audit',
                    'severity': 'high',
                    'title': f'Política {pid} expuesta (Origen ALL + Servicio ALL)',
                    'description': f'Permite tráfico desde cualquier IP usando cualquier servicio.',
                    'recommendation': 'Restringir al menos los servicios permitidos.',
                    'related_policy_id': pid,
                    'related_vdom': p.get('vdom'),
                    'cli_remediation': StaticAnalyzer._generate_remediation_cli(pid, p) 
                })
                
            # 3. Medium: Open Interface usage (Zone mismatch?)
            # If srcintf is 'any', it bypasses zone checks often.
            if is_any_src_intf and is_accept:
                 recommendations.append({
                    'category': 'security_audit',
                    'severity': 'medium',
                    'title': f'Política {pid} usa interfaz "any" en origen',
                    'description': 'El uso de "any" en interfaces reduce la visibilidad y segmentación.',
                    'recommendation': 'Especificar interfaces o zonas concretas.',
                    'related_policy_id': pid,
                    'related_vdom': p.get('vdom')
                })

        return recommendations

    @staticmethod
    def _generate_remediation_cli(pid, policy_data):
        """Simple remediation suggestion"""
        return f"""config firewall policy
    edit {pid}
    set comments "AUDIT: Detected as overly permissive"
    # Suggestion:
    # set srcaddr "specific-group"
    # set service "HTTP" "HTTPS"
    next
end"""
