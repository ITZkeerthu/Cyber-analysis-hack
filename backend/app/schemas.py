from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime

class EvidenceUpload(BaseModel):
    case_id: str
    logs: List[Dict[str, Any]]

class EvidenceResponse(BaseModel):
    id: int
    case_id: str
    timestamp: datetime
    user: str
    ip_address: str
    device: str
    file_path: str
    action: str
    
    class Config:
        from_attributes = True

class RuleAnalysisResult(BaseModel):
    rule_score: float
    flagged_entities: List[Dict[str, Any]]
    triggered_rules: List[str]

class AnomalyResult(BaseModel):
    anomaly_scores: Dict[str, float]
    overall_anomaly_score: float
    flagged_users: List[str]

class GraphNode(BaseModel):
    id: str
    type: str
    label: str
    risk_score: float = 0.0

class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str
    timestamp: Optional[datetime] = None

class GraphResult(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    central_nodes: List[Dict[str, Any]]

class SimilarityResult(BaseModel):
    matched_case_id: Optional[str]
    similarity_score: float
    similar_cases: List[Dict[str, Any]]

class RAGResult(BaseModel):
    relevant_cases: List[Dict[str, Any]]
    relevant_laws: List[Dict[str, Any]]
    context: str

class LLMReport(BaseModel):
    summary: str
    timeline: List[Dict[str, Any]]
    suspicious_entities: List[Dict[str, Any]]
    matched_case_comment: str
    risk_level: str

class FCIScore(BaseModel):
    confidence_score: float
    risk_level: str
    component_scores: Dict[str, float]

class FullAnalysisResult(BaseModel):
    case_id: str
    rule_analysis: RuleAnalysisResult
    anomaly_analysis: AnomalyResult
    graph_analysis: GraphResult
    similarity_analysis: SimilarityResult
    rag_context: RAGResult
    llm_report: LLMReport
    fci_score: FCIScore
    final_report: str

class AnalysisRequest(BaseModel):
    case_id: str

class ReportRequest(BaseModel):
    case_id: str
    include_graph: bool = True