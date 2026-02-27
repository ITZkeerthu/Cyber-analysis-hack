from fastapi import FastAPI, File, UploadFile, Form, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import List, Optional
import json
import os
from datetime import datetime

from .database import get_db, init_db
from .models import Case, Evidence, Report
from .schemas import (
    EvidenceUpload, EvidenceResponse, RuleAnalysisResult,
    AnomalyResult, GraphResult, SimilarityResult, RAGResult,
    LLMReport, FCIScore, FullAnalysisResult, AnalysisRequest
)
from .ingestion import EvidenceIngestor
from .rule_engine import RuleEngine
from .anomaly_detection import AnomalyDetector
from .graph_engine import GraphEngine
from .case_similarity import CaseSimilarityEngine
from .rag_engine import RAGEngine
from .llm_engine import LLMEngine
from .fci_engine import FCIEngine
from .orchestrator import AnalysisOrchestrator
from .security import generate_case_id

app = FastAPI(
    title="Hybrid Offline Forensic Intelligence System",
    description="Secure evidence ingestion and forensic analysis platform",
    version="1.0.0"
)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    init_db()
    print("[INFO] Database initialized")

# ==================== CASE MANAGEMENT ====================

@app.post("/cases/create")
async def create_case(
    title: str = Form(...),
    description: str = Form(""),
    db: Session = Depends(get_db)
) -> dict:
    """Create a new forensic case."""
    case_id = generate_case_id()
    
    case = Case(
        case_id=case_id,
        title=title,
        description=description,
        status="open",
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    
    db.add(case)
    db.commit()
    
    return {
        "case_id": case_id,
        "title": title,
        "status": "created",
        "created_at": case.created_at.isoformat()
    }

@app.get("/cases/{case_id}")
async def get_case(case_id: str, db: Session = Depends(get_db)) -> dict:
    """Get case details."""
    case = db.query(Case).filter(Case.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    return {
        "case_id": case.case_id,
        "title": case.title,
        "description": case.description,
        "status": case.status,
        "fci_score": case.fci_score,
        "risk_level": case.risk_level,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None
    }

@app.get("/cases")
async def list_cases(db: Session = Depends(get_db)) -> list:
    """List all cases."""
    cases = db.query(Case).all()
    return [
        {
            "case_id": c.case_id,
            "title": c.title,
            "status": c.status,
            "fci_score": c.fci_score,
            "risk_level": c.risk_level
        }
        for c in cases
    ]

# ==================== EVIDENCE UPLOAD ====================

@app.post("/upload")
async def upload_evidence(
    case_id: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
) -> dict:
    """Upload evidence file (JSON or CSV)."""
    
    # Verify case exists
    case = db.query(Case).filter(Case.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    # Read file content
    content = await file.read()
    content_str = content.decode('utf-8')
    
    # Determine format and ingest
    ingestor = EvidenceIngestor(db)
    
    try:
        if file.filename.endswith('.json'):
            evidence = ingestor.ingest_json(case_id, content_str)
        elif file.filename.endswith('.csv'):
            evidence = ingestor.ingest_csv(case_id, content_str)
        else:
            # Try JSON first, then CSV
            try:
                evidence = ingestor.ingest_json(case_id, content_str)
            except:
                evidence = ingestor.ingest_csv(case_id, content_str)
        
        return {
            "status": "success",
            "case_id": case_id,
            "records_ingested": len(evidence),
            "filename": file.filename
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse file: {str(e)}")

@app.post("/upload/json")
async def upload_json_logs(
    request: EvidenceUpload,
    db: Session = Depends(get_db)
) -> dict:
    """Upload logs as JSON array."""
    
    # Verify case exists
    case = db.query(Case).filter(Case.case_id == request.case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    ingestor = EvidenceIngestor(db)
    evidence = ingestor.ingest_logs(request.case_id, request.logs)
    
    return {
        "status": "success",
        "case_id": request.case_id,
        "records_ingested": len(evidence)
    }

@app.get("/evidence/{case_id}")
async def get_evidence(case_id: str, db: Session = Depends(get_db)) -> list:
    """Get all evidence for a case."""
    evidence = db.query(Evidence).filter(Evidence.case_id == case_id).all()
    return [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "user": e.user,
            "ip_address": e.ip_address,
            "device": e.device,
            "file_path": e.file_path,
            "action": e.action
        }
        for e in evidence
    ]

# ==================== ANALYSIS ENDPOINTS ====================

@app.post("/analyze/rules")
async def analyze_rules(case_id: str = Form(...), db: Session = Depends(get_db)) -> dict:
    """Run rule-based analysis."""
    engine = RuleEngine(db)
    result = engine.analyze(case_id)
    return result

@app.post("/analyze/anomaly")
async def analyze_anomaly(case_id: str = Form(...), db: Session = Depends(get_db)) -> dict:
    """Run anomaly detection."""
    detector = AnomalyDetector(db)
    result = detector.analyze(case_id)
    return result

@app.get("/graph/{case_id}")
async def get_graph(case_id: str, db: Session = Depends(get_db)) -> dict:
    """Get graph visualization data."""
    engine = GraphEngine(db)
    result = engine.build_graph(case_id)
    return result

@app.post("/analyze/similarity")
async def analyze_similarity(case_id: str = Form(...), db: Session = Depends(get_db)) -> dict:
    """Run case similarity analysis."""
    graph_engine = GraphEngine(db)
    graph_data = graph_engine.build_graph(case_id)
    
    similarity_engine = CaseSimilarityEngine(db)
    result = similarity_engine.compute_similarity(case_id, graph_data)
    return result

@app.post("/retrieve")
async def rag_retrieve(query: str = Form(...)) -> dict:
    """RAG retrieval for query."""
    rag = RAGEngine()
    result = rag.retrieve(query)
    return result

@app.post("/generate-report")
async def generate_report(
    case_id: str = Form(...),
    db: Session = Depends(get_db)
) -> dict:
    """Generate LLM report."""
    # Gather all analysis data
    rule_engine = RuleEngine(db)
    anomaly_detector = AnomalyDetector(db)
    graph_engine = GraphEngine(db)
    similarity_engine = CaseSimilarityEngine(db)
    rag_engine = RAGEngine()
    llm_engine = LLMEngine()
    
    rule_result = rule_engine.analyze(case_id)
    anomaly_result = anomaly_detector.analyze(case_id)
    graph_result = graph_engine.build_graph(case_id)
    similarity_result = similarity_engine.compute_similarity(case_id, graph_result)
    
    retrieval_query = {
        "flagged_entities": rule_result.get("flagged_entities", []),
        "triggered_rules": rule_result.get("triggered_rules", []),
        "anomaly_scores": anomaly_result.get("anomaly_scores", {})
    }
    rag_result = rag_engine.retrieve_for_case(retrieval_query)
    
    analysis_data = {
        "case_id": case_id,
        "rule_analysis": rule_result,
        "anomaly_analysis": anomaly_result,
        "graph_analysis": graph_result,
        "similarity_analysis": similarity_result,
        "rag_context": rag_result
    }
    
    llm_report = await llm_engine.generate_report(analysis_data)
    return llm_report

@app.post("/fci")
async def calculate_fci(case_id: str = Form(...), db: Session = Depends(get_db)) -> dict:
    """Calculate Forensic Confidence Index."""
    rule_engine = RuleEngine(db)
    anomaly_detector = AnomalyDetector(db)
    graph_engine = GraphEngine(db)
    similarity_engine = CaseSimilarityEngine(db)
    fci_engine = FCIEngine()
    
    rule_result = rule_engine.analyze(case_id)
    anomaly_result = anomaly_detector.analyze(case_id)
    graph_result = graph_engine.build_graph(case_id)
    similarity_result = similarity_engine.compute_similarity(case_id, graph_result)
    
    analysis_data = {
        "rule_analysis": rule_result,
        "anomaly_analysis": anomaly_result,
        "graph_analysis": graph_result,
        "similarity_analysis": similarity_result
    }
    
    result = fci_engine.calculate(analysis_data)
    return result

@app.post("/full-analysis")
async def run_full_analysis(
    case_id: str = Form(...),
    db: Session = Depends(get_db)
) -> dict:
    """Run complete forensic analysis pipeline."""
    orchestrator = AnalysisOrchestrator(db)
    result = await orchestrator.run_full_analysis(case_id)
    return result

# ==================== REPORT ENDPOINTS ====================

@app.get("/report/{case_id}")
async def get_report(case_id: str, db: Session = Depends(get_db)) -> dict:
    """Get generated report for case."""
    report = db.query(Report).filter(Report.case_id == case_id).order_by(
        Report.created_at.desc()
    ).first()
    
    if not report:
        # Try to run analysis
        orchestrator = AnalysisOrchestrator(db)
        status = orchestrator.get_analysis_status(case_id)
        if status.get("exists"):
            raise HTTPException(status_code=404, detail="Report not yet generated. Run full-analysis first.")
        else:
            raise HTTPException(status_code=404, detail="Case not found")
    
    # Parse stored JSON report
    try:
        report_data = json.loads(report.generated_report)
        return report_data
    except:
        return {
            "summary": report.summary,
            "timeline": report.timeline,
            "suspicious_entities": report.suspicious_entities,
            "risk_level": report.risk_level,
            "confidence_score": report.confidence_score,
            "matched_case_comment": report.matched_case_comment,
            "created_at": report.created_at.isoformat() if report.created_at else None
        }

@app.get("/status/{case_id}")
async def get_analysis_status(case_id: str, db: Session = Depends(get_db)) -> dict:
    """Get analysis status for case."""
    orchestrator = AnalysisOrchestrator(db)
    return orchestrator.get_analysis_status(case_id)

# ==================== HEALTH CHECK ====================

@app.get("/health")
async def health_check() -> dict:
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "Hybrid Offline Forensic Intelligence System",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/")
async def root() -> dict:
    """API root."""
    return {
        "name": "Hybrid Offline Forensic Intelligence System",
        "version": "1.0.0",
        "endpoints": [
            "/cases/create",
            "/cases",
            "/upload",
            "/upload/json",
            "/analyze/rules",
            "/analyze/anomaly",
            "/graph/{case_id}",
            "/analyze/similarity",
            "/retrieve",
            "/generate-report",
            "/fci",
            "/full-analysis",
            "/report/{case_id}",
            "/health"
        ]
    }