import numpy as np
import json
import networkx as nx
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict
from sqlalchemy.orm import Session
from sklearn.metrics.pairwise import cosine_similarity
from .models import CaseGraph, Case
from .config import SIMILARITY_THRESHOLD

class CaseSimilarityEngine:
    def __init__(self, db: Session):
        self.db = db
    
    def compute_similarity(self, case_id: str, current_graph_data: Dict[str, Any]) -> Dict[str, Any]:
        """Find similar historical cases."""
        # Extract feature vector from current graph
        current_vector = self._extract_graph_features(current_graph_data)
        
        # Get all stored case graphs
        stored_cases = self.db.query(CaseGraph).filter(
            CaseGraph.case_id != case_id
        ).all()
        
        if not stored_cases:
            return {
                "matched_case_id": None,
                "similarity_score": 0.0,
                "similar_cases": []
            }
        
        similarities = []
        
        for stored in stored_cases:
            stored_vector = stored.feature_vector
            if stored_vector:
                # Convert to numpy arrays
                stored_vec = np.array(stored_vector)
                current_vec = np.array(current_vector)
                
                # Ensure same dimension
                max_dim = max(len(stored_vec), len(current_vec))
                stored_vec = np.pad(stored_vec, (0, max_dim - len(stored_vec)))
                current_vec = np.pad(current_vec, (0, max_dim - len(current_vec)))
                
                # Calculate cosine similarity
                sim = cosine_similarity([stored_vec], [current_vec])[0][0]
                
                if sim >= SIMILARITY_THRESHOLD:
                    case = self.db.query(Case).filter(Case.case_id == stored.case_id).first()
                    similarities.append({
                        "case_id": stored.case_id,
                        "similarity_score": round(float(sim), 4),
                        "title": case.title if case else "Unknown",
                        "risk_level": case.risk_level if case else "Unknown"
                    })
        
        # Sort by similarity
        similarities.sort(key=lambda x: x["similarity_score"], reverse=True)
        
        best_match = similarities[0] if similarities else None
        
        return {
            "matched_case_id": best_match["case_id"] if best_match else None,
            "similarity_score": best_match["similarity_score"] if best_match else 0.0,
            "similar_cases": similarities[:5]  # Top 5
        }
    
    def _extract_graph_features(self, graph_data: Dict[str, Any]) -> List[float]:
        """Extract numerical features from graph for comparison."""
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])
        
        features = []
        
        # Feature 1: Total node count
        features.append(len(nodes))
        
        # Feature 2: Total edge count
        features.append(len(edges))
        
        # Feature 3: Node type distribution
        type_counts = defaultdict(int)
        for node in nodes:
            node_type = node.get("type", "unknown")
            type_counts[node_type] += 1
        
        for node_type in ["user", "file", "device", "ip", "process"]:
            features.append(type_counts.get(node_type, 0))
        
        # Feature 4: Relation type distribution
        rel_counts = defaultdict(int)
        for edge in edges:
            rel = edge.get("relation", "UNKNOWN")
            rel_counts[rel] += 1
        
        for rel in ["EXECUTED", "ACCESSED", "CONNECTED", "ASSIGNED", "FROM"]:
            features.append(rel_counts.get(rel, 0))
        
        # Feature 5: Average degree (edge density)
        avg_degree = len(edges) / max(len(nodes), 1)
        features.append(avg_degree)
        
        # Feature 6: Average risk score
        risk_scores = [n.get("risk_score", 0) for n in nodes]
        avg_risk = np.mean(risk_scores) if risk_scores else 0
        features.append(avg_risk)
        
        # Feature 7: Max risk score
        max_risk = max(risk_scores) if risk_scores else 0
        features.append(max_risk)
        
        # Feature 8: High-risk node count (risk > 0.5)
        high_risk_count = sum(1 for r in risk_scores if r > 0.5)
        features.append(high_risk_count)
        
        # Normalize features to 0-1 range
        features = self._normalize_features(features)
        
        return features
    
    def _normalize_features(self, features: List[float]) -> List[float]:
        """Normalize feature vector."""
        max_vals = [
            100,  # node count
            200,  # edge count
            20, 20, 20, 20, 20,  # node types
            50, 50, 50, 50, 50,  # relations
            10,   # avg degree
            1.0,  # avg risk
            1.0,  # max risk
            100   # high risk count
        ]
        
        normalized = []
        for i, val in enumerate(features):
            max_val = max_vals[i] if i < len(max_vals) else 100
            normalized.append(min(val / max_val, 1.0))
        
        return normalized
    
    def store_case_graph(self, case_id: str, graph_data: Dict[str, Any]):
        """Store case graph with its feature vector."""
        feature_vector = self._extract_graph_features(graph_data)
        
        existing = self.db.query(CaseGraph).filter(
            CaseGraph.case_id == case_id
        ).first()
        
        if existing:
            existing.graph_data = graph_data
            existing.feature_vector = feature_vector
        else:
            case_graph = CaseGraph(
                case_id=case_id,
                graph_data=graph_data,
                feature_vector=feature_vector
            )
            self.db.add(case_graph)
        
        self.db.commit()
    
    def find_pattern_matches(self, case_id: str, pattern: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find cases matching a specific pattern."""
        # Simple pattern matching based on node/edge patterns
        stored_cases = self.db.query(CaseGraph).all()
        matches = []
        
        for stored in stored_cases:
            graph_data = stored.graph_data
            if not graph_data:
                continue
            
            score = self._pattern_match_score(graph_data, pattern)
            if score > 0.5:
                matches.append({
                    "case_id": stored.case_id,
                    "match_score": round(score, 4)
                })
        
        return matches
    
    def _pattern_match_score(self, graph_data: Dict[str, Any], pattern: Dict[str, Any]) -> float:
        """Calculate how well a graph matches a pattern."""
        # Pattern can specify required node types, edge types
        required_nodes = pattern.get("node_types", [])
        required_edges = pattern.get("edge_types", [])
        
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])
        
        node_types = {n.get("type") for n in nodes}
        edge_types = {e.get("relation") for e in edges}
        
        node_match = sum(1 for t in required_nodes if t in node_types) / max(len(required_nodes), 1)
        edge_match = sum(1 for t in required_edges if t in edge_types) / max(len(required_edges), 1)
        
        return (node_match + edge_match) / 2