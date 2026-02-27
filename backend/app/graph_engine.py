import networkx as nx
from datetime import datetime
from typing import List, Dict, Any, Set, Tuple
from collections import defaultdict
from sqlalchemy.orm import Session
from .models import Evidence, Entity
import json

class GraphEngine:
    def __init__(self, db: Session):
        self.db = db
        self.G = nx.DiGraph()
    
    def build_graph(self, case_id: str) -> Dict[str, Any]:
        """Build graph from evidence."""
        evidence = self.db.query(Evidence).filter(Evidence.case_id == case_id).all()
        
        if not evidence:
            return {
                "nodes": [],
                "edges": [],
                "central_nodes": []
            }
        
        self.G.clear()
        
        # Build nodes and edges
        entities_map = defaultdict(set)  # type -> set of values
        connections = []  # (source_id, target_id, relation, timestamp)
        
        for e in evidence:
            # Create unique IDs for entities
            user_id = f"user_{e.user}"
            device_id = f"device_{e.device}"
            ip_id = f"ip_{e.ip_address}"
            
            if e.file_path:
                file_id = f"file_{hash(e.file_path) % 10000}"
            else:
                file_id = None
            
            process_id = f"process_{e.action}"
            
            # Add nodes
            self.G.add_node(user_id, type="user", label=e.user, risk_score=0.0)
            self.G.add_node(device_id, type="device", label=e.device, risk_score=0.0)
            self.G.add_node(ip_id, type="ip", label=e.ip_address, risk_score=0.0)
            self.G.add_node(process_id, type="process", label=e.action, risk_score=0.0)
            
            if file_id:
                self.G.add_node(file_id, type="file", label=e.file_path.split('/')[-1] if '/' in e.file_path else e.file_path, risk_score=0.0)
            
            # Track entities
            entities_map["user"].add(e.user)
            entities_map["device"].add(e.device)
            entities_map["ip"].add(e.ip_address)
            if e.file_path:
                entities_map["file"].add(e.file_path)
            entities_map["process"].add(e.action)
            
            # Add edges
            edges_to_add = []
            
            # User -> Process (EXECUTED)
            edges_to_add.append((user_id, process_id, "EXECUTED", e.timestamp))
            
            # Process -> File (ACCESSED)
            if file_id:
                edges_to_add.append((process_id, file_id, "ACCESSED", e.timestamp))
            
            # User -> Device (CONNECTED)
            edges_to_add.append((user_id, device_id, "CONNECTED", e.timestamp))
            
            # Device -> IP (ASSIGNED)
            edges_to_add.append((device_id, ip_id, "ASSIGNED", e.timestamp))
            
            # User -> IP (FROM)
            edges_to_add.append((user_id, ip_id, "FROM", e.timestamp))
            
            for src, tgt, rel, ts in edges_to_add:
                if self.G.has_edge(src, tgt):
                    # Update edge weight
                    self.G[src][tgt]["weight"] = self.G[src][tgt].get("weight", 1) + 1
                else:
                    self.G.add_edge(src, tgt, relation=rel, timestamp=ts.isoformat() if ts else None, weight=1)
        
        # Calculate centrality
        centrality_scores = self._calculate_centrality()
        
        # Update node risk scores based on centrality
        for node_id, score in centrality_scores.items():
            if node_id in self.G:
                self.G.nodes[node_id]["risk_score"] = min(score, 1.0)
        
        # Get central nodes
        central_nodes = self._get_central_nodes(centrality_scores)
        
        # Convert to response format
        nodes = []
        for node_id, data in self.G.nodes(data=True):
            nodes.append({
                "id": node_id,
                "type": data.get("type", "unknown"),
                "label": data.get("label", node_id),
                "risk_score": data.get("risk_score", 0.0)
            })
        
        edges = []
        for src, tgt, data in self.G.edges(data=True):
            edges.append({
                "source": src,
                "target": tgt,
                "relation": data.get("relation", "UNKNOWN"),
                "timestamp": data.get("timestamp")
            })
        
        return {
            "nodes": nodes,
            "edges": edges,
            "central_nodes": central_nodes,
            "centrality_scores": {k: round(v, 4) for k, v in centrificality_scores.items()}
        }
    
    def _calculate_centrality(self) -> Dict[str, float]:
        """Calculate various centrality metrics."""
        if len(self.G) == 0:
            return {}
        
        # Degree centrality (influence)
        try:
            degree_cent = nx.degree_centrality(self.G)
        except:
            degree_cent = {n: 0.0 for n in self.G.nodes()}
        
        # Betweenness centrality (gatekeeper)
        try:
            betweenness_cent = nx.betweenness_centrality(self.G)
        except:
            betweenness_cent = {n: 0.0 for n in self.G.nodes()}
        
        # PageRank (importance)
        try:
            pagerank = nx.pagerank(self.G)
        except:
            pagerank = {n: 0.0 for n in self.G.nodes()}
        
        # Combine scores
        combined = {}
        for node in self.G.nodes():
            combined[node] = (
                0.4 * degree_cent.get(node, 0) +
                0.3 * betweenness_cent.get(node, 0) +
                0.3 * pagerank.get(node, 0)
            )
        
        return combined
    
    def _get_central_nodes(self, centrality_scores: Dict[str, float], top_n: int = 5) -> List[Dict[str, Any]]:
        """Get top central/suspicious nodes."""
        sorted_nodes = sorted(
            centrality_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )[:top_n]
        
        result = []
        for node_id, score in sorted_nodes:
            if score > 0.1:  # Only include significant nodes
                node_data = self.G.nodes[node_id]
                result.append({
                    "id": node_id,
                    "type": node_data.get("type", "unknown"),
                    "label": node_data.get("label", node_id),
                    "centrality_score": round(score, 4),
                    "risk_score": round(score, 4)
                })
        
        return result
    
    def traverse_from_node(self, start_node_id: str, max_depth: int = 3) -> List[Dict[str, Any]]:
        """BFS traversal from a suspicious node."""
        if start_node_id not in self.G:
            return []
        
        visited = set([start_node_id])
        queue = [(start_node_id, 0)]
        paths = []
        
        while queue:
            current, depth = queue.pop(0)
            
            if depth >= max_depth:
                continue
            
            for successor in self.G.successors(current):
                if successor not in visited:
                    visited.add(successor)
                    queue.append((successor, depth + 1))
                    edge_data = self.G[current][successor]
                    paths.append({
                        "from": current,
                        "to": successor,
                        "relation": edge_data.get("relation", "UNKNOWN"),
                        "depth": depth + 1
                    })
        
        return paths
    
    def get_suspicious_paths(self, case_id: str, suspicious_nodes: List[str]) -> List[Dict[str, Any]]:
        """Find paths between suspicious nodes."""
        all_paths = []
        
        for i, source in enumerate(suspicious_nodes):
            for target in suspicious_nodes[i+1:]:
                try:
                    path = nx.shortest_path(self.G, source, target)
                    all_paths.append({
                        "source": source,
                        "target": target,
                        "path": path,
                        "length": len(path)
                    })
                except nx.NetworkXNoPath:
                    continue
        
        return all_paths
    
    def serialize_graph(self) -> str:
        """Serialize graph to JSON for storage."""
        data = {
            "nodes": [
                {"id": n, **self.G.nodes[n]}
                for n in self.G.nodes()
            ],
            "edges": [
                {"source": u, "target": v, **d}
                for u, v, d in self.G.edges(data=True)
            ]
        }
        return json.dumps(data)
    
    def load_graph(self, serialized: str):
        """Load graph from serialized JSON."""
        data = json.loads(serialized)
        self.G.clear()
        
        for node_data in data.get("nodes", []):
            node_id = node_data.pop("id")
            self.G.add_node(node_id, **node_data)
        
        for edge_data in data.get("edges", []):
            source = edge_data.pop("source")
            target = edge_data.pop("target")
            self.G.add_edge(source, target, **edge_data)