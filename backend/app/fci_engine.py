from typing import Dict, Any, List
from .config import FCI_WEIGHTS

class FCIEngine:
    """Forensic Confidence Index Engine"""
    
    def __init__(self):
        self.weights = FCI_WEIGHTS
    
    def calculate(self, analysis_components: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate Forensic Confidence Index.
        
        FCI = weighted sum of:
        - rule_score (30%)
        - anomaly_score (25%)
        - centrality_score (20%)
        - similarity_score (15%)
        - evidence_consistency (10%)
        """
        
        # Extract component scores
        rule_analysis = analysis_components.get("rule_analysis", {})
        anomaly_analysis = analysis_components.get("anomaly_analysis", {})
        graph_analysis = analysis_components.get("graph_analysis", {})
        similarity_analysis = analysis_components.get("similarity_analysis", {})
        
        # Component 1: Rule Score (0-1, higher = more violations)
        rule_score = rule_analysis.get("rule_score", 0.0)
        
        # Component 2: Anomaly Score (0-1, higher = more anomalous)
        anomaly_score = anomaly_analysis.get("overall_anomaly_score", 0.0)
        
        # Component 3: Centrality Score (max centrality of central nodes)
        centrality_score = self._calculate_centrality_component(graph_analysis)
        
        # Component 4: Similarity Score (already 0-1)
        similarity_score = similarity_analysis.get("similarity_score", 0.0)
        
        # Component 5: Evidence Consistency
        evidence_consistency = self._calculate_consistency_score(analysis_components)
        
        # Calculate weighted FCI
        fci = (
            self.weights["rule_score"] * rule_score +
            self.weights["anomaly_score"] * anomaly_score +
            self.weights["centrality_score"] * centrality_score +
            self.weights["similarity_score"] * similarity_score +
            self.weights["evidence_consistency"] * evidence_consistency
        )
        
        # Determine risk level
        risk_level = self._determine_risk_level(fci, {
            "rule_score": rule_score,
            "anomaly_score": anomaly_score,
            "centrality_score": centrality_score,
            "similarity_score": similarity_score
        })
        
        return {
            "confidence_score": round(fci, 4),
            "risk_level": risk_level,
            "component_scores": {
                "rule_score": round(rule_score, 4),
                "anomaly_score": round(anomaly_score, 4),
                "centrality_score": round(centrality_score, 4),
                "similarity_score": round(similarity_score, 4),
                "evidence_consistency": round(evidence_consistency, 4)
            },
            "interpretation": self._generate_interpretation(fci, risk_level),
            "confidence_breakdown": self._generate_breakdown(fci, {
                "rule_score": rule_score,
                "anomaly_score": anomaly_score,
                "centrality_score": centrality_score,
                "similarity_score": similarity_score,
                "evidence_consistency": evidence_consistency
            })
        }
    
    def _calculate_centrality_component(self, graph_analysis: Dict[str, Any]) -> float:
        """Calculate graph centrality component score."""
        central_nodes = graph_analysis.get("central_nodes", [])
        
        if not central_nodes:
            return 0.0
        
        # Average centrality score of central nodes
        scores = [node.get("centrality_score", 0) for node in central_nodes]
        avg_score = sum(scores) / len(scores) if scores else 0
        
        # Normalize: higher centrality = higher suspicion
        return min(avg_score * 2, 1.0)  # Scale up, cap at 1
    
    def _calculate_consistency_score(self, components: Dict[str, Any]) -> float:
        """Calculate evidence consistency score."""
        rule_analysis = components.get("rule_analysis", {})
        anomaly_analysis = components.get("anomaly_analysis", {})
        
        # Check if rule and anomaly detections align
        rule_flagged = set()
        for entity in rule_analysis.get("flagged_entities", []):
            if entity.get("type") == "user":
                rule_flagged.add(entity.get("value", "").lower())
        
        anomaly_flagged = set(
            user.lower() 
            for user in anomaly_analysis.get("flagged_users", [])
        )
        
        if not rule_flagged and not anomaly_flagged:
            return 0.5  # Neutral if no flags
        
        # Calculate overlap
        if rule_flagged and anomaly_flagged:
            overlap = len(rule_flagged.intersection(anomaly_flagged))
            total = len(rule_flagged.union(anomaly_flagged))
            consistency = overlap / total if total > 0 else 0
            
            # Higher consistency = higher confidence in findings
            return 0.5 + (consistency * 0.5)
        
        # Only one detection method found issues
        return 0.4
    
    def _determine_risk_level(self, fci: float, components: Dict[str, float]) -> str:
        """Determine overall risk level based on FCI and components."""
        
        # Multiple high components = higher risk
        high_components = sum(1 for score in components.values() if score > 0.6)
        
        if fci >= 0.7 or high_components >= 3:
            return "High"
        elif fci >= 0.4 or high_components >= 1:
            return "Medium"
        else:
            return "Low"
    
    def _generate_interpretation(self, fci: float, risk_level: str) -> str:
        """Generate human-readable interpretation."""
        interpretations = {
            "High": f"Forensic Confidence Index of {fci:.2f} indicates strong evidence of security incident. Multiple detection methods have identified suspicious activity requiring immediate investigation.",
            "Medium": f"Forensic Confidence Index of {fci:.2f} suggests potential security concerns. Some indicators of suspicious activity detected, warranting further review.",
            "Low": f"Forensic Confidence Index of {fci:.2f} indicates limited suspicious activity. Standard monitoring recommended."
        }
        return interpretations.get(risk_level, "Unable to determine risk level.")
    
    def _generate_breakdown(self, fci: float, components: Dict[str, float]) -> Dict[str, Any]:
        """Generate detailed breakdown of FCI calculation."""
        breakdown = {}
        
        for component, weight in self.weights.items():
            score = components.get(component, 0)
            weighted = score * weight
            breakdown[component] = {
                "raw_score": round(score, 4),
                "weight": weight,
                "weighted_contribution": round(weighted, 4),
                "percentage_of_fci": round((weighted / fci * 100) if fci > 0 else 0, 2)
            }
        
        return breakdown
    
    def compare_cases(self, fci_scores: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compare FCI scores across multiple cases."""
        if not fci_scores:
            return {"comparison": "No cases to compare"}
        
        scores = [case.get("confidence_score", 0) for case in fci_scores]
        
        return {
            "average_fci": round(sum(scores) / len(scores), 4),
            "highest_fci": round(max(scores), 4),
            "lowest_fci": round(min(scores), 4),
            "high_risk_count": sum(1 for s in fci_scores if s.get("risk_level") == "High"),
            "medium_risk_count": sum(1 for s in fci_scores if s.get("risk_level") == "Medium"),
            "low_risk_count": sum(1 for s in fci_scores if s.get("risk_level") == "Low")
        }