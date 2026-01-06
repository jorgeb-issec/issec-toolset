import google.generativeai as genai
import json
from typing import Dict, Any, List

class AIService:
    _initialized = False

    @classmethod
    def initialize(cls, api_key: str):
        if not cls._initialized and api_key:
            genai.configure(api_key=api_key)
            cls._initialized = True

    @classmethod
    def analyze_security_logs(cls, stats: Dict[str, Any], interesting_logs: List[Dict[str, Any]], api_key: str = None, focus_areas: List[str] = None, policies: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Send log stats to Gemini for security analysis
        """
        # Configure GenAI with specific key or fallback
        if api_key:
             genai.configure(api_key=api_key)
        elif not cls._initialized:
             return {"error": "AI Service not initialized and no key provided", "recommendations": []}

        model = genai.GenerativeModel('gemini-1.5-flash')
        
        prompt = f"""
        Act as a Senior Network Security Analyst and Fortinet Expert. Analyze the following FortiGate firewall log statistics and samples.
        
        Specific Focus Areas:
        {', '.join(focus_areas) if focus_areas else 'General Security Audit'}

        Data Statistics:
        {json.dumps(stats, default=str)}

        Sample Denied/Interesting Logs:
        {json.dumps(interesting_logs, default=str)}
        
        Related Policy Configurations (MATCHED from DB):
        {json.dumps(policies, default=str) if policies else 'No policy data available'}

        Task:
        1. Context: You are auditing FortiGate logs. We have identified traffic hitting specific policies.
        2. AUDIT CONFIGURATION: Check the 'Related Policy Configurations' for the policy IDs involved. 
           - LOOK FOR: 'ALL', 'ANY', '0.0.0.0/0' in Source, Destination, or Service.
           - LOOK FOR: Overly permissive settings (e.g., Action ACCEPT with no security profiles).
        3. TRAFFIC ANALYSIS: Compare the ACTUAL traffic (Stats/Logs) vs the CONFIGURATION.
           - Example: Policy allows 'ALL' service, but traffic is only 'HTTPS'. Recommendation: Restrict service to HTTPS.
        4. REMEDIATION: Provide specific FortiGate CLI commands to fix the issue.

        Output Format (JSON Only):
        {{
            "analysis_summary": "Exec summary...",
            "recommendations": [
                {{
                    "title": "Clear issue title (e.g. Policy 5 allows ALL services)",
                    "description": "Explain WHY this is a risk based on the config vs traffic.",
                    "action": "Human readable action (e.g. Change service from ALL to HTTPS)",
                    "cli_remediation": "config firewall policy\\n edit <ID>\\n  set service HTTPS\\n next\\nend",
                    "severity": "critical|high|medium|low",
                    "related_policy_id": "ID of related policy",
                    "category": "security|optimization|compliance"
                }}
            ]
        }}
        """

        try:
            response = model.generate_content(prompt)
            # Cleanup Markdown code blocks if present
            text = response.text.replace('```json', '').replace('```', '').strip()
            return json.loads(text)
        except Exception as e:
            # Try to partial parse if possible or return error
            return {"error": str(e), "recommendations": []}
