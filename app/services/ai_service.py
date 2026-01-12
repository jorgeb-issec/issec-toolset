import google.generativeai as genai
import json
from typing import Dict, Any, List, Optional

class AIService:
    _initialized = False

    @classmethod
    def initialize(cls, api_key: str):
        if not cls._initialized and api_key:
            genai.configure(api_key=api_key)
            cls._initialized = True

    @classmethod
    def analyze_security_logs(
        cls, 
        stats: Dict[str, Any], 
        interesting_logs: List[Dict[str, Any]], 
        api_key: str = None, 
        focus_areas: List[str] = None, 
        policies: Dict[str, Any] = None,
        interfaces: List[Dict[str, Any]] = None,  # v1.3.0 - Interface context
        vdoms: List[str] = None,                   # v1.3.0 - VDOM context
        generate_new_policies: bool = False,       # v1.3.0 - Generate new policies
        segmentation: Dict[str, Any] = None        # v1.3.0 - Segmentation filters
    ) -> Dict[str, Any]:
        """
        Send log stats to Gemini for security analysis with interface/zone context.
        
        v1.3.0 enhancements:
        - interfaces: list of {name, role, zone, ip} for context
        - vdoms: list of VDOM names being analyzed
        - generate_new_policies: if True, generate optimized policy suggestions
        - segmentation: filters applied {src_intf, dst_intf, vdom, device}
        """
        # Configure GenAI with specific key or fallback
        if api_key:
             genai.configure(api_key=api_key)
        elif not cls._initialized:
             return {"error": "AI Service not initialized and no key provided", "recommendations": []}

        model = genai.GenerativeModel('gemini-1.5-flash')
        
        # Build interface context string
        interface_context = ""
        if interfaces:
            interface_context = "\n".join([
                f"- {i.get('name')}: role={i.get('role', 'N/A')}, zone={i.get('zone', 'N/A')}, ip={i.get('ip', 'N/A')}"
                for i in interfaces
            ])
        
        # Build segmentation context
        seg_context = ""
        if segmentation:
            parts = []
            if segmentation.get('vdom'):
                parts.append(f"VDOM: {segmentation['vdom']}")
            if segmentation.get('src_intf'):
                parts.append(f"Source Interface: {segmentation['src_intf']}")
            if segmentation.get('dst_intf'):
                parts.append(f"Destination Interface: {segmentation['dst_intf']}")
            if parts:
                seg_context = "Analysis Scope: " + ", ".join(parts)
        
        # Build the enhanced prompt
        prompt = f"""
        Act as a Senior Network Security Analyst and Fortinet Expert. Analyze the following FortiGate firewall log statistics and samples.
        
        Specific Focus Areas:
        {', '.join(focus_areas) if focus_areas else 'General Security Audit'}
        
        {seg_context}

        === INTERFACE TOPOLOGY ===
        {interface_context if interface_context else "No interface data available - analyze based on log srcintf/dstintf fields"}
        
        === VDOMs Being Analyzed ===
        {', '.join(vdoms) if vdoms else 'All VDOMs / root'}

        === Data Statistics ===
        {json.dumps(stats, default=str)}

        === Sample Denied/Interesting Logs ===
        {json.dumps(interesting_logs[:50], default=str)}
        
        === Related Policy Configurations (MATCHED from DB) ===
        {json.dumps(policies, default=str) if policies else 'No policy data available'}

        === TASK ===
        1. **Context Analysis**: You are auditing FortiGate logs filtered by the scope above.
        
        2. **AUDIT CONFIGURATION**: Check the 'Related Policy Configurations':
           - LOOK FOR: 'ALL', 'ANY', '0.0.0.0/0' in Source, Destination, or Service
           - LOOK FOR: Overly permissive settings (Action ACCEPT with no security profiles)
           - IDENTIFY: Which interface/zone combinations are involved
        
        3. **TRAFFIC FLOW ANALYSIS**: Analyze actual traffic patterns:
           - Map traffic flows between interfaces (srcintf → dstintf)
           - Identify most used services per interface pair
           - Detect anomalies in zone-to-zone traffic
        
        4. **ZERO TRUST ENFORCEMENT & POLICY OPTIMIZATION** (CRITICAL):
           
           Adopt a "Zero Trust" philosophy: "Never Trust, Always Verify".
           Everything not explicitly allowed should be denied.
           
           For overly permissive policies (Any/Any, or broad ranges), you MUST:
           a) Analyze the ACTUAL traffic flows in the logs (Src -> Dst : Service).
           b) Identify the valid business patterns vs noise.
           c) Generate a **STRICT ALLOW-LIST** policy that permits ONLY the observed necessary traffic.
           d) Suggest REMOVING or DISABLING the original permissive policy after the new specific one is verified.
           
           **CRITICAL VIOLATIONS TO FLAG:**
           - Lateral movement (Internal -> Internal) using admin protocols (RDP, SSH, WinRM) without specific justification.
           - Prod/DMZ access from non-secure zones.
           - Clear text protocols (Telnet, FTP, HTTP) crossing zone boundaries.

           Example of specific remediation (Whitelist):
           "The traffic shows 95% HTTPS to 10.0.0.5. Restrict Policy 10 completely."
           CLI:
           config firewall policy
             edit <ID>
             set srcaddr "Specific_Host"
             set dstaddr "Specific_Server"
             set service "HTTPS"
             set action accept
             next
           end
        
        {"5. **NEW POLICY GENERATION**: Generate granular Zero Trust policies for observed traffic flows. Create multiple specific policies rather than one broad one if multiple distinct flows exist." if generate_new_policies else ""}
        
        6. **CONSOLIDATION & DEDUPLICATION** (CRITICAL):
           - If you identify multiple hosts, policies, or events with the SAME root cause (e.g. "Insecure WiFi Protocol", "Clear text password", "Multiple sources scanning port 445"), DO NOT create separate recommendations for each instance.
           - Create ONE single 'summary' recommendation.
           - In the 'description', state the total COUNT of affected entities and list 3-5 examples.
           - Ensure 'affected_count' reflects the total volume.
           - This is vital to avoid overwhelming the user with thousands of identical alerts.

        === OUTPUT FORMAT (JSON Only) ===
        {{
            "analysis_summary": "Executive summary focusing on interface/zone security posture...",
            "traffic_flows": [
                {{
                    "src_intf": "LAN",
                    "src_zone": "Internal",
                    "dst_intf": "WAN",
                    "dst_zone": "External",
                    "top_services": ["HTTPS", "DNS"],
                    "log_count": 500,
                    "risk_level": "medium"
                }}
            ],
            "recommendations": [
                {{
                    "title": "Clear issue title (e.g. Policy 5 allows ALL services from LAN to WAN)",
                    "description": "Explain WHY this is a risk based on interface roles and traffic patterns.",
                    "action": "Human readable action",
                    "cli_remediation": "config firewall policy\\n edit <ID>\\n  set service HTTPS DNS\\n next\\nend",
                    "severity": "critical|high|medium|low",
                    "related_policy_id": "ID of related policy",
                    "category": "security|optimization|compliance",
                    "affected_interfaces": ["LAN", "WAN"]
                }}
            ],
            "new_policies": [
                {{
                    "name": "Allow-LAN-to-WAN-Web",
                    "description": "Specific policy for web traffic based on observed patterns",
                    "src_intf": "LAN",
                    "dst_intf": "WAN",
                    "src_addr": "all",
                    "dst_addr": "all",
                    "service": ["HTTPS", "HTTP"],
                    "action": "accept",
                    "security_profiles": {{
                        "av-profile": "default",
                        "webfilter-profile": "default"
                    }},
                    "cli_command": "config firewall policy\\n  edit 0\\n    set name \\"Allow-LAN-to-WAN-Web\\"\\n    set srcintf \\"LAN\\"\\n    set dstintf \\"WAN\\"\\n    set srcaddr \\"all\\"\\n    set dstaddr \\"all\\"\\n    set service \\"HTTPS\\" \\"HTTP\\"\\n    set action accept\\n    set av-profile \\"default\\"\\n    set webfilter-profile \\"default\\"\\n    set logtraffic all\\n  next\\nend"
                }}
            ]
        }}
        """

        try:
            response = model.generate_content(prompt)
            # Cleanup Markdown code blocks if present
            text = response.text.replace('```json', '').replace('```', '').strip()
            return json.loads(text)
        except json.JSONDecodeError as e:
            # Try to extract partial JSON
            return {"error": f"JSON parse error: {str(e)}", "raw_response": response.text[:500], "recommendations": []}
        except Exception as e:
            return {"error": str(e), "recommendations": []}
    
    @classmethod
    def generate_policy_from_traffic(
        cls,
        traffic_pattern: Dict[str, Any],
        api_key: str = None
    ) -> Dict[str, Any]:
        """
        Generate a specific FortiGate policy based on observed traffic pattern.
        
        traffic_pattern: {
            "src_intf": "LAN",
            "dst_intf": "WAN",
            "services": ["HTTPS", "DNS"],
            "src_ips": ["192.168.1.0/24"],
            "dst_ips": ["any"],
            "log_count": 1000
        }
        """
        if api_key:
            genai.configure(api_key=api_key)
        elif not cls._initialized:
            return {"error": "AI Service not initialized"}
        
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        prompt = f"""
        As a FortiGate firewall expert, create an optimized firewall policy based on this traffic pattern:
        
        {json.dumps(traffic_pattern, default=str)}
        
        Requirements:
        1. Generate a descriptive policy name following Fortinet naming conventions
        2. Use specific services instead of "ALL"
        3. Include appropriate security profiles (AV, WebFilter, IPS if applicable)
        4. Enable logging
        5. Provide complete CLI command
        
        Output JSON:
        {{
            "policy_name": "...",
            "cli_command": "config firewall policy\\n...",
            "explanation": "Why this policy configuration is recommended"
        }}
        """
        
        try:
            response = model.generate_content(prompt)
            text = response.text.replace('```json', '').replace('```', '').strip()
            return json.loads(text)
        except Exception as e:
            return {"error": str(e)}
