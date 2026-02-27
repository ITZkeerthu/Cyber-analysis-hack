import json
import httpx
from typing import Dict, Any, Optional
from datetime import datetime
from .config import OLLAMA_BASE_URL, LLM_MODEL

class LLMEngine:
    def __init__(self):
        self.base_url = OLLAMA_BASE_URL
        self.model = LLM_MODEL
    
    async def generate_report(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate forensic report using local LLM."""
        
        # Build evidence-grounded prompt
        prompt = self._build_prompt(analysis_data)
        
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json",
                        "options": {
                            "temperature": 0.3,
                            "top_p": 0.9,
                            "num_ctx": 4096
                        }
                    }
                )
                
                if response.status_code == 200:
                    result = response.json()
                    generated_text = result.get("response", "")
                    
                    # Parse JSON output
                    try:
                        parsed = json.loads(generated_text)
                        return self._validate_and_format(parsed, analysis_data)
                    except json.JSONDecodeError:
                        # If JSON parsing fails, extract structured info
                        return self._extract_from_text(generated_text, analysis_data)
                else:
                    return self._fallback_report(analysis_data)
                    
        except Exception as e:
            print(f"LLM Error: {e}")
            return self._fallback_report(analysis_data)
    
    def _build_prompt(self, data: Dict[str, Any]) -> str:
        """Build structured prompt from analysis data."""
        
        rule_analysis = data.get("rule_analysis", {})
        anomaly_analysis = data.get("anomaly_analysis", {})
        graph_analysis = data.get("graph_analysis", {})
        similarity_analysis = data.get("similarity_analysis", {})
        rag_context = data.get("rag_context", {})
        case_id = data.get("case_id", "UNKNOWN")
        
        prompt = f"""You are a senior digital forensics analyst. Generate a forensic investigation report based on the provided evidence and analysis.

CASE ID: {case_id}

## RULE-BASED ANALYSIS
Rule Score: {rule_analysis.get('rule_score', 0)}
Triggered Rules: {', '.join(rule_analysis.get('triggered_rules', []))}
Flagged Entities: {json.dumps(rule_analysis.get('flagged_entities', []), indent=2)}

## ANOMALY DETECTION
Anomaly Score: {anomaly_analysis.get('overall_anomaly_score', 0)}
Flagged Users: {', '.join(anomaly_analysis.get('flagged_users', []))}
User Anomaly Scores: {json.dumps(anomaly_analysis.get('anomaly_scores', {}), indent=2)}

## GRAPH ANALYSIS
Central Suspicious Nodes: {json.dumps(graph_analysis.get('central_nodes', []), indent=2)}
Total Nodes: {len(graph_analysis.get('nodes', []))}
Total Edges: {len(graph_analysis.get('edges', []))}

## CASE SIMILARITY
Similarity Score: {similarity_analysis.get('similarity_score', 0)}
Matched Case ID: {similarity_analysis.get('matched_case_id', 'None')}
Similar Cases: {json.dumps(similarity_analysis.get('similar_cases', []), indent=2)}

## REFERENCE CONTEXT
{rag_context.get('context', 'No reference context available.')}

Generate a comprehensive forensic report in the following JSON format:
{{
    "summary": "Brief executive summary of the incident (2-3 sentences)",
    "timeline": [
        {{"time": "timestamp", "event": "description", "severity": "Low|Medium|High"}}
    ],
    "suspicious_entities": [
        {{"entity": "name", "type": "user|file|ip|device", "risk_factors": ["list"], "recommendation": "action"}}
    ],
    "matched_case_comment": "Comment on similarities to historical cases",
    "risk_level": "Low|Medium|High",
    "key_findings": ["list of key findings"],
    "recommendations": ["immediate actions"]
}}

Provide only valid JSON output."""
        
        return prompt
    
    def _validate_and_format(self, parsed: Dict[str, Any], original_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and format LLM output."""
        return {
            "summary": parsed.get("summary", "No summary generated."),
            "timeline": parsed.get("timeline", []),
            "suspicious_entities": parsed.get("suspicious_entities", []),
            "matched_case_comment": parsed.get("matched_case_comment", ""),
            "risk_level": self._validate_risk_level(parsed.get("risk_level", "Medium")),
            "key_findings": parsed.get("key_findings", []),
            "recommendations": parsed.get("recommendations", []),
            "generated_at": datetime.utcnow().isoformat()
        }
    
    def _extract_from_text(self, text: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract structured info from non-JSON text."""
        # Simple extraction fallback
        return {
            "summary": text[:500] if text else "Report generation incomplete.",
            "timeline": [],
            "suspicious_entities": [],
            "matched_case_comment": data.get("similarity_analysis", {}).get("matched_case_id", ""),
            "risk_level": "Medium",
            "key_findings": [],
            "recommendations": ["Review flagged entities manually"],
            "generated_at": datetime.utcnow().isoformat()
        }
    
    def _fallback_report(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate fallback report when LLM is unavailable."""
        rule_analysis = data.get("rule_analysis", {})
        anomaly_analysis = data.get("anomaly_analysis", {})
        
        triggered_rules = rule_analysis.get("triggered_rules", [])
        flagged_users = anomaly_analysis.get("flagged_users", [])
        
        findings = []
        if triggered_rules:
            findings.append(f"Rule violations detected: {', '.join(triggered_rules)}")
        if flagged_users:
            findings.append(f"Anomalous user behavior: {', '.join(flagged_users)}")
        
        risk_level = "High" if (triggered_rules and flagged_users) else "Medium" if (triggered_rules or flagged_users) else "Low"
        
        return {
            "summary": f"Automated forensic analysis completed. {len(triggered_rules)} rules triggered, {len(flagged_users)} anomalous users detected.",
            "timeline": [],
            "suspicious_entities": rule_analysis.get("flagged_entities", []),
            "matched_case_comment": data.get("similarity_analysis", {}).get("matched_case_id", "None"),
            "risk_level": risk_level,
            "key_findings": findings,
            "recommendations": ["Review flagged entities", "Investigate anomalous users", "Check system logs"],
            "generated_at": datetime.utcnow().isoformat(),
            "note": "LLM fallback report generated"
        }
    
    def _validate_risk_level(self, risk: str) -> str:
        """Validate risk level value."""
        valid_levels = ["Low", "Medium", "High"]
        risk = risk.capitalize()
        return risk if risk in valid_levels else "Medium"
    
    async def check_ollama_health(self) -> bool:
        """Check if Ollama is available."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                return response.status_code == 200
        except:
            return False