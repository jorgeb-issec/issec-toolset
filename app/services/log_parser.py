"""
FortiAnalyzer Log Parser Service
Parses logs in the FortiAnalyzer CSV-like format
"""
import re
from datetime import datetime
from typing import Dict, List, Any, Optional
import uuid
# Import StaticAnalyzer for shared logic if needed, 
# or just remove the duplicated method if it's no longer used internally here.
# LogAnalyzer's main job is dynamic analysis (logs).
# The 'analyze_policies' method was static. 



class FortiLogParser:
    """
    Parser for FortiGate/FortiAnalyzer log formats
    
    Supports:
    - CSV-like format from FortiAnalyzer export
    - Syslog format
    - JSON format
    """
    
    # Protocol number to name mapping
    PROTOCOLS = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        47: 'GRE',
        50: 'ESP',
        51: 'AH',
        58: 'ICMPv6',
        89: 'OSPF',
        132: 'SCTP'
    }
    
    @classmethod
    def parse_fortianalyzer_line(cls, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single line from FortiAnalyzer export.
        
        Handles formats like:
        - itime=1767622897
        - date="2026-01-05"
        - devid="FG200FT921904709"
        - Empty fields
        
        Args:
            line: Raw log line
            
        Returns:
            Parsed log entry as dictionary, or None if parsing fails
        """
        if not line or not line.strip():
            return None
        
        result = {}
        
        # Split by comma, but we need to handle the quoted format carefully
        # Each field is enclosed in double quotes: "field=value" or "field=""value"""
        
        # Use regex to find all field=value pairs
        # Pattern explanation:
        # "([^"=]+)=  - Match opening quote, capture field name (no quotes or equals), then equals
        # (?:""([^"]*)""|([^"]*))  - Match either ""value"" (escaped quotes) or plain value
        # "  - Match closing quote
        
        # Try pattern for escaped quotes first: "field=""value"""
        pattern_escaped = r'"([^"=]+)=""([^"]*)"""'
        matches = re.findall(pattern_escaped, line)
        for field, value in matches:
            if field and value:  # Skip empty values
                result[field] = value.strip()
        
        # Then try pattern for numeric/simple values: "field=value"
        pattern_simple = r'"([^"=]+)=([^",]+)"'
        matches_simple = re.findall(pattern_simple, line)
        for field, value in matches_simple:
            if field and field not in result:  # Don't overwrite escaped values
                value = value.strip().strip('"')  # Clean up any stray quotes
                if value:
                    result[field] = value
        
        # Handle special case where value might have escaped quotes inside
        # Pattern: "field=""value with ""nested"" quotes"""
        # For now, the above patterns should handle most cases
        
        return result if result else None
    
    @classmethod
    def parse_file(cls, content: str) -> List[Dict[str, Any]]:
        """
        Parse entire log file content
        
        Args:
            content: Full file content
            
        Returns:
            List of parsed log entries
        """
        entries = []
        
        for line in content.strip().split('\n'):
            entry = cls.parse_fortianalyzer_line(line)
            if entry:
                entries.append(entry)
        
        return entries
    
    @classmethod
    def normalize_entry(cls, raw_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a raw parsed entry to standard field names
        
        Args:
            raw_entry: Raw parsed log entry
            
        Returns:
            Normalized entry with consistent field names
        """
        normalized = {
            'raw_data': raw_entry
        }
        
        # Timestamps
        if 'date' in raw_entry and 'time' in raw_entry:
            try:
                dt_str = f"{raw_entry['date']} {raw_entry['time']}"
                normalized['timestamp'] = datetime.strptime(dt_str, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                pass
        
        if 'itime' in raw_entry:
            normalized['itime'] = cls._to_int(raw_entry['itime'])
        
        if 'eventtime' in raw_entry:
            normalized['eventtime'] = cls._to_int(raw_entry['eventtime'])
        
        # Device Info
        normalized['devid'] = raw_entry.get('devid')
        normalized['devname'] = raw_entry.get('devname')
        normalized['vdom'] = raw_entry.get('vd') or raw_entry.get('vdom')
        
        # Log Type
        normalized['log_id'] = raw_entry.get('logid')
        normalized['log_type'] = raw_entry.get('type')
        normalized['subtype'] = raw_entry.get('subtype')
        normalized['level'] = raw_entry.get('level')
        
        # Source
        normalized['src_intf'] = raw_entry.get('srcintf')
        normalized['src_intf_role'] = raw_entry.get('srcintfrole')
        normalized['src_ip'] = raw_entry.get('srcip')
        normalized['src_port'] = cls._to_int(raw_entry.get('srcport'))
        normalized['src_country'] = raw_entry.get('srccountry')
        normalized['src_city'] = raw_entry.get('srccity')
        normalized['src_mac'] = raw_entry.get('srcmac') or raw_entry.get('mastersrcmac')
        
        # Destination
        normalized['dst_intf'] = raw_entry.get('dstintf')
        normalized['dst_intf_role'] = raw_entry.get('dstintfrole')
        normalized['dst_ip'] = raw_entry.get('dstip')
        normalized['dst_port'] = cls._to_int(raw_entry.get('dstport'))
        normalized['dst_country'] = raw_entry.get('dstcountry')
        normalized['dst_city'] = raw_entry.get('dstcity')
        
        # Policy
        normalized['policy_id'] = cls._to_int(raw_entry.get('policyid'))
        normalized['policy_uuid'] = raw_entry.get('poluuid')
        normalized['policy_type'] = raw_entry.get('policytype')
        
        # Traffic
        normalized['action'] = raw_entry.get('action')
        normalized['protocol'] = cls._to_int(raw_entry.get('proto'))
        normalized['service'] = raw_entry.get('service')
        normalized['app'] = raw_entry.get('app')
        normalized['app_cat'] = raw_entry.get('appcat')
        
        # Bytes/Packets
        normalized['sent_bytes'] = cls._to_int(raw_entry.get('sentbyte'))
        normalized['rcvd_bytes'] = cls._to_int(raw_entry.get('rcvdbyte'))
        normalized['sent_pkts'] = cls._to_int(raw_entry.get('sentpkt'))
        normalized['rcvd_pkts'] = cls._to_int(raw_entry.get('rcvdpkt'))
        normalized['duration'] = cls._to_int(raw_entry.get('duration'))
        
        # Session
        normalized['session_id'] = cls._to_int(raw_entry.get('sessionid'))
        normalized['nat_type'] = raw_entry.get('trandisp')
        
        # Threats
        threats_str = raw_entry.get('threats', '[]')
        if threats_str and threats_str != '[]':
            try:
                # Parse threats array if present
                normalized['threats'] = threats_str
            except:
                pass
        
        return normalized
    
    @staticmethod
    def _to_int(value: Any) -> Optional[int]:
        """Safely convert value to integer"""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
    
    @classmethod
    def get_protocol_name(cls, proto_num: int) -> str:
        """Get protocol name from number"""
        return cls.PROTOCOLS.get(proto_num, f'PROTO-{proto_num}')


class LogAnalyzer:
    """
    Analyzes parsed logs for security insights and recommendations
    """
    
    @classmethod
    def analyze_logs(cls, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Perform comprehensive analysis on a set of logs
        
        Args:
            logs: List of normalized log entries
            
        Returns:
            Analysis results with stats and recommendations
        """
        stats = cls._calculate_stats(logs)
        recommendations = cls._generate_recommendations(logs, stats)
        
        return {
            'log_count': len(logs),
            'stats': stats,
            'recommendations': recommendations
        }
    
    @classmethod
    def _calculate_stats(cls, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate statistics from logs"""
        stats = {
            'by_action': {},
            'by_type': {},
            'by_policy': {},
            'by_vdom': {},
            'by_src_country': {},
            'by_dst_country': {},
            'by_service': {},
            'by_app': {},
            'top_talkers': {},
            'top_destinations': {},
            'denied_connections': [],
            'high_volume_sessions': []
        }
        
        for log in logs:
            # Count by action
            action = log.get('action', 'unknown')
            stats['by_action'][action] = stats['by_action'].get(action, 0) + 1
            
            # Count by type
            log_type = log.get('log_type', 'unknown')
            stats['by_type'][log_type] = stats['by_type'].get(log_type, 0) + 1
            
            # Count by policy
            policy_id = log.get('policy_id')
            if policy_id:
                key = str(policy_id)
                stats['by_policy'][key] = stats['by_policy'].get(key, 0) + 1
            
            # Count by VDOM
            vdom = log.get('vdom', 'root')
            stats['by_vdom'][vdom] = stats['by_vdom'].get(vdom, 0) + 1
            
            # Count by countries
            src_country = log.get('src_country')
            if src_country and src_country != 'Reserved':
                stats['by_src_country'][src_country] = stats['by_src_country'].get(src_country, 0) + 1
            
            dst_country = log.get('dst_country')
            if dst_country and dst_country != 'Reserved':
                stats['by_dst_country'][dst_country] = stats['by_dst_country'].get(dst_country, 0) + 1
            
            # Count by service
            service = log.get('service')
            if service:
                stats['by_service'][service] = stats['by_service'].get(service, 0) + 1

            # NEW: Track policy for risky countries
            policy_id = str(log.get('policy_id', 'unknown'))
            if src_country in ['China', 'Russia', 'North Korea', 'Iran']:
                if 'risky_country_policies' not in stats:
                    stats['risky_country_policies'] = {}
                if src_country not in stats['risky_country_policies']:
                        stats['risky_country_policies'][src_country] = {}
                
                stats['risky_country_policies'][src_country][policy_id] = stats['risky_country_policies'][src_country].get(policy_id, 0) + 1
            
            # Count by app
            app = log.get('app')
            if app:
                stats['by_app'][app] = stats['by_app'].get(app, 0) + 1
            
            # Top talkers (source IPs)
            src_ip = log.get('src_ip')
            if src_ip:
                if src_ip not in stats['top_talkers']:
                    stats['top_talkers'][src_ip] = {'count': 0, 'bytes': 0}
                stats['top_talkers'][src_ip]['count'] += 1
                stats['top_talkers'][src_ip]['bytes'] += (log.get('sent_bytes') or 0) + (log.get('rcvd_bytes') or 0)
            
            # Top destinations
            dst_ip = log.get('dst_ip')
            if dst_ip:
                if dst_ip not in stats['top_destinations']:
                    stats['top_destinations'][dst_ip] = {'count': 0, 'bytes': 0}
                stats['top_destinations'][dst_ip]['count'] += 1
                stats['top_destinations'][dst_ip]['bytes'] += (log.get('sent_bytes') or 0) + (log.get('rcvd_bytes') or 0)
            
            # Track denied connections
            if action in ['deny', 'blocked', 'dropped']:
                stats['denied_connections'].append({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'dst_port': log.get('dst_port'),
                    'policy_id': policy_id,
                    'timestamp': str(log.get('timestamp'))
                })
            
            # Track high volume sessions
            total_bytes = (log.get('sent_bytes') or 0) + (log.get('rcvd_bytes') or 0)
            if total_bytes > 100_000_000:  # > 100 MB
                stats['high_volume_sessions'].append({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'bytes': total_bytes,
                    'duration': log.get('duration'),
                    'policy_id': policy_id
                })
        
        # NEW: Track flows per policy for Least Privilege Analysis
        if policy_id and policy_id != 'unknown':
            if 'policy_flows' not in stats:
                stats['policy_flows'] = {}
            if policy_id not in stats['policy_flows']:
                stats['policy_flows'][policy_id] = set()
            
            # Limit flow tracking per policy
            if len(stats['policy_flows'][policy_id]) < 50:
                # tuple of (src, dst, service, protocol)
                flow = (src_ip or 'all', dst_ip or 'all', service or 'ALL', log.get('proto', 'TCP'))
                stats['policy_flows'][policy_id].add(flow)
        
        # Sort and limit top talkers/destinations
        stats['top_talkers'] = dict(
            sorted(stats['top_talkers'].items(), key=lambda x: x[1]['bytes'], reverse=True)[:20]
        )
        stats['top_destinations'] = dict(
            sorted(stats['top_destinations'].items(), key=lambda x: x[1]['bytes'], reverse=True)[:20]
        )
        
        # Convert sets to lists
        if 'policy_flows' in stats:
             for pid in stats['policy_flows']:
                 stats['policy_flows'][pid] = list(stats['policy_flows'][pid])

        # Limit denied connections sample
        stats['denied_connections'] = stats['denied_connections'][:100]
        stats['high_volume_sessions'] = stats['high_volume_sessions'][:50]
        
        return stats
    
    @classmethod
    def _generate_recommendations(cls, logs: List[Dict[str, Any]], stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        # Check for high deny rates
        total = len(logs)
        if total > 0:
            deny_count = stats['by_action'].get('deny', 0) + stats['by_action'].get('blocked', 0)
            deny_rate = deny_count / total
            
            if deny_rate > 0.3:
                recommendations.append({
                    'category': 'security',
                    'severity': 'medium',
                    'title': 'Alta tasa de conexiones denegadas',
                    'description': f'{deny_rate:.1%} de las conexiones fueron denegadas ({deny_count}/{total})',
                    'recommendation': 'Revisar las reglas de firewall y verificar si hay intentos de acceso no autorizados o configuraciones incorrectas.',
                    'affected_count': deny_count
                })
        
        # Check for policies with high traffic
        for policy_id, count in stats['by_policy'].items():
            if count > total * 0.5:  # > 50% of traffic
                recommendations.append({
                    'category': 'optimization',
                    'severity': 'info',
                    'title': f'Política {policy_id} concentra alto volumen de tráfico',
                    'description': f'La política {policy_id} maneja {count}/{total} conexiones ({count/total:.1%})',
                    'recommendation': 'Considerar dividir esta política para mejor granularidad y control.',
                    'related_policy_id': int(policy_id),
                    'affected_count': count
                })
        
        # Check for unusual countries
        suspicious_countries = ['China', 'Russia', 'North Korea', 'Iran']
        for country in suspicious_countries:
            if country in stats['by_src_country']:
                count = stats['by_src_country'][country]
                
                # Find top policy for this country
                related_pid = None
                if 'risky_country_policies' in stats and country in stats['risky_country_policies']:
                    # Get the policy ID with the most hits for this country
                    pids = stats['risky_country_policies'][country]
                    if pids:
                        related_pid = max(pids, key=pids.get)
                        if related_pid == 'unknown': related_pid = None

                # Generate GeoIP Block CLI
                country_code = {'China': 'CN', 'Russia': 'RU', 'North Korea': 'KP', 'Iran': 'IR'}.get(country, 'UNK')
                cli_cmd = ""
                if country_code != 'UNK':
                    cli_cmd = f"""config firewall address
    edit "Block_{country}"
        set type geography
        set country "{country_code}"
    next
end
config firewall policy
    edit 1
    # Move to top
    set srcintf "any"
    set dstintf "any"
    set srcaddr "Block_{country}"
    set dstaddr "all"
    set action deny
    set schedule "always"
    set service "ALL"
    set logtraffic all
    next
end"""

                recommendations.append({
                    'category': 'security',
                    'severity': 'high',
                    'title': f'Tráfico desde país de alto riesgo: {country}',
                    'description': f'Se detectaron {count} conexiones originadas desde {country}',
                    'recommendation': f'Revisar si el tráfico desde {country} es esperado. Considerar bloquear por geolocalización o revisar la Política {related_pid if related_pid else "correspondiente"}.',
                    'cli_remediation': cli_cmd,

                    'affected_count': count,
                    'related_policy_id': related_pid,
                    'related_vdom': next((l.get('vdom') for l in logs if str(l.get('policy_id')) == str(related_pid)), None) if related_pid else None
                })
        
        # Check for client-rst (connection resets)
        client_rst = stats['by_action'].get('client-rst', 0)
        
        # Find top policy for client-rst
        rst_pid = None
        if client_rst > 0:
            # Re-scan logs for this specific stat to avoid bloat in _calculate_stats if preferred, OR assume we add it to stats.
            # Let's do a quick pass here since logs are available
            rst_counts = {}
            for log in logs:
                if log.get('action') == 'client-rst':
                    pid = log.get('policy_id')
                    if pid:
                        rst_counts[pid] = rst_counts.get(pid, 0) + 1
            if rst_counts:
                rst_pid = max(rst_counts, key=rst_counts.get)

        if client_rst > total * 0.1:
            recommendations.append({
                'category': 'optimization',
                'severity': 'low',
                'title': 'Alto número de conexiones reseteadas por cliente',
                'description': f'{client_rst} conexiones terminadas con client-rst',
                'recommendation': 'Puede indicar timeouts, aplicaciones mal comportadas o problemas de red. Revisar la política afectada.',

                'affected_count': client_rst,
                'related_policy_id': rst_pid,
                'related_vdom': next((l.get('vdom') for l in logs if str(l.get('policy_id')) == str(rst_pid)), None) if rst_pid else None
            })
        
        # Check for unscanned apps
        unscanned = 0
        unscanned_counts = {}
        for log in logs:
            if log.get('app_cat') == 'unscanned':
                unscanned += 1
                pid = log.get('policy_id')
                if pid:
                    unscanned_counts[pid] = unscanned_counts.get(pid, 0) + 1
        
        unscanned_pid = None
        if unscanned_counts:
            unscanned_pid = max(unscanned_counts, key=unscanned_counts.get)

        if unscanned > total * 0.2:
            recommendations.append({
                'category': 'security',
                'severity': 'medium',
                'title': 'Alto porcentaje de aplicaciones no escaneadas',
                'description': f'{unscanned}/{total} conexiones con appcat=unscanned',
                'recommendation': 'Habilitar Deep Inspection o SSL Inspection para mejor visibilidad del tráfico en la política afectada.',
                'affected_count': unscanned,
                'related_policy_id': unscanned_pid,
                'related_vdom': next((l.get('vdom') for l in logs if str(l.get('policy_id')) == str(unscanned_pid)), None) if unscanned_pid else None,
                'cli_remediation': f"""config firewall policy
    edit {unscanned_pid}
    set note "Review for SSL Inspection"
    # Suggestion: set ssl-ssh-profile "deep-inspection"
    next
end""" if unscanned_pid else None
            })
        
        return recommendations

    @classmethod
    def _generate_least_privilege_cli(cls, pid: str, stats: Dict[str, Any], policy_data: Dict[str, Any] = None) -> str:
        """
        Generate CLI to RESTRICT a policy based on observed traffic, NOT disable.
        Creates specific sub-policies and modifies the original to be more restrictive.
        """
        if not stats or 'policy_flows' not in stats:
            # No traffic data - suggest manual review instead of auto-disable
            return f"""# No traffic data available for Policy {pid}
# Review manually and restrict to specific:
# - Source addresses (avoid 'all')
# - Destination addresses (avoid 'all')
# - Services (avoid 'ALL')
config firewall policy
    edit {pid}
    set comments "PENDING REVIEW - Restrict based on actual traffic"
    # set srcaddr "specific_object"
    # set dstaddr "specific_object"
    # set service "HTTPS" "SSH"
    next
end"""
        
        flows = stats['policy_flows'].get(str(pid), [])
        if not flows:
            return f"""# No recorded traffic flows for Policy {pid}
# If this policy has no traffic, consider disabling after monitoring period
config firewall policy
    edit {pid}
    set comments "NO TRAFFIC DETECTED - Review for removal"
    next
end"""

        # Analyze flows to determine most common services/IPs
        services_used = {}
        src_ips = {}
        dst_ips = {}
        
        for flow in flows:
            src, dst, svc, proto = flow
            services_used[svc] = services_used.get(svc, 0) + 1
            if src and src != 'all':
                src_ips[src] = src_ips.get(src, 0) + 1
            if dst and dst != 'all':
                dst_ips[dst] = dst_ips.get(dst, 0) + 1
        
        # Get top services (limit to 10)
        top_services = sorted(services_used.items(), key=lambda x: x[1], reverse=True)[:10]
        top_src = sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:5]
        top_dst = sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Build service restriction
        svc_list = ' '.join(f'"{s[0]}"' for s in top_services if s[0] and s[0] != 'ALL')
        if not svc_list:
            svc_list = '"HTTPS" "HTTP" "DNS"  # Default safe services'
        
        cli = f"""# ═══════════════════════════════════════════════════════════════
# POLICY {pid} OPTIMIZATION - Based on {len(flows)} observed traffic flows
# ═══════════════════════════════════════════════════════════════

# OPTION 1: RESTRICT EXISTING POLICY (Recommended)
# Modify to allow only observed services instead of ALL
config firewall policy
    edit {pid}
    set service {svc_list}
    set comments "RESTRICTED - Only observed services allowed"
    set logtraffic all
    next
end

"""
        
        # Generate sub-policies if there are clear patterns
        if len(top_services) > 3 and len(top_dst) >= 2:
            cli += """# OPTION 2: SPLIT INTO SPECIFIC POLICIES
# Create granular policies per destination/service combination
"""
            count = 0
            for svc_name, svc_count in top_services[:5]:
                if not svc_name or svc_name == 'ALL':
                    continue
                count += 1
                cli += f"""config firewall policy
    edit 0
    set name "Split-P{pid}-{svc_name[:8]}"
    set srcintf {f'"{policy_data.get("src_intf", "any")}"' if policy_data else '"any"'}
    set dstintf {f'"{policy_data.get("dst_intf", "any")}"' if policy_data else '"any"'}
    set srcaddr "all"
    set dstaddr "all"
    set service "{svc_name}"
    set action accept
    set schedule "always"
    set logtraffic all
    set comments "Split from Policy {pid}"
    next
end
"""
                if count >= 3:
                    break
            
            cli += f"""
# After creating split policies, disable original:
config firewall policy
    edit {pid}
    set status disable
    set comments "REPLACED by specific policies Split-P{pid}-*"
    next
end
"""
        
        return cli

    @classmethod
    def analyze_policies(cls, policies: List[Dict[str, Any]], stats: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        DEPRECATED: Use StaticAnalyzer.analyze_policies instead.
        Kept for backward compatibility if called directly.
        """
        from app.services.static_analyzer import StaticAnalyzer
        return StaticAnalyzer.analyze_policies(policies, stats)

