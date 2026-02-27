from typing import Dict, Any
from sqlalchemy.orm import Session
from .ingestion import EvidenceIngestor
from .rule_engine import RuleEngine
from .anomaly_detection import AnomalyDetector
from .graph_engine import GraphEngine
from .case_similarity import CaseSimilarityEngine
from .rag_engine import RAGEngine
from .llm_engine import LLMEngine
from .fci_engine import FCIEngine
from .models import Case, Report
import asyncio

class AnalysisOrchestrator:
    """
    LangGraph-style orchestration pipeline:
    Upload → Rules → Anomaly → Graph → Similarity → RAG → LLM → FCI → Final Report
    """
    
    def __init__(self, db: Session):
        self.db = db
        self.ingestor = EvidenceIngestor(db)
        self.rule_engine = RuleEngine(db)
        self.anomaly_detector = AnomalyDetector(db)
        self.graph_engine = GraphEngine(db)
        self.similarity_engine = CaseSimilarityEngine(db)
        self.rag_engine = RAGEngine()
        self.llm_engine = LLMEngine()
        self.fci_engine = FCIEngine()
    
    async def run_full_analysis(self, case_id: str) -> Dict[str, Any]:
        """Execute complete forensic analysis pipeline."""
        
        # Check if case exists
        case = self.db.query(Case).filter(Case.case_id == case_id).first()
        if not case:
            return {"error": f"Case {case_id} not found"}
        
        # Step 1: Rule-based Analysis
        print(f"[Orchestrator] Running rule analysis for {case_id}...")
        rule_result = self.rule_engine.analyze(case_id)
        
        # Step 2: Anomaly Detection
        print(f"[Orchestrator] Running anomaly detection for {case_id}...")
        anomaly_result = self.anomaly_detector.analyze(case_id)
        
        # Step 3: Graph Construction
        print(f"[Orchestrator] Building graph for {case_id}...")
        graph_result = self.graph_engine.build_graph(case_id)
        
        # Store graph for similarity comparison
        self.similarity_engine.store_case_graph(case_id, graph_result)
        
        # Step 4: Case Similarity
        print(f"[Orchestrator] Computing case similarity for {case_id}...")
        similarity_result = self.similarity_engine.compute_similarity(case_id, graph_result)
        
        # Step 5: RAG Retrieval
        print(f"[Orchestrator] Retrieving context via RAG for {case_id}...")
        retrieval_query = {
            "flagged_entities": rule_result.get("flagged_entities", []),
            "triggered_rules": rule_result.get("triggered_rules", []),
            "anomaly_scores": anomaly_result.get("anomaly_scores", {})
        }
        rag_result = self.rag_engine.retrieve_for_case(retrieval_query)
        
        # Step 6: LLM Report Generation
        print(f"[Orchestrator] Generating LLM report for {case_id}...")
        analysis_data = {
            "case_id": case_id,
            "rule_analysis": rule_result,
            "anomaly_analysis": anomaly_result,
            "graph_analysis": graph_result,
            "similarity_analysis": similarity_result,
            "rag_context": rag_result
        }
        llm_report = await self.llm_engine.generate_report(analysis_data)
        
        # Step 7: FCI Calculation
        print(f"[Orchestrator] Calculating FCI for {case_id}...")
        fci_result = self.fci_engine.calculate(analysis_data)
        
        # Update case with FCI
        case.fci_score = fci_result["confidence_score"]
        case.risk_level = fci_result["risk_level"]
        self.db.commit()
        
        # Compile final report
        final_report = self._compile_final_report(
            case_id, rule_result, anomaly_result, graph_result,
            similarity_result, rag_result, llm_report, fci_result
        )
        
        # Store report in database
        self._store_report(case_id, final_report)
        
        print(f"[Orchestrator] Analysis complete for {case_id}")
        
        return final_report
    
    def _compile_final_report(self, case_id: str, rule_result: Dict, 
                              anomaly_result: Dict, graph_result: Dict,
                              similarity_result: Dict, rag_result: Dict,
                              llm_report: Dict, fci_result: Dict) -> Dict[str, Any]:
        """Compile all analysis results into final report."""
        
        return {
            "case_id": case_id,
            "analysis_timestamp": __import__('datetime').datetime.utcnow().isoformat(),
            "executive_summary": llm_report.get("summary", ""),
            "forensic_confidence_index": fci_result,
            "risk_assessment": {
                "level": fci_result["risk_level"],
                "score": fci_result["confidence_score"],
                "interpretation": fci_result["interpretation"]
            },
            "findings": {
                "rule_based": rule_result,
                "anomaly_detection": anomaly_result,
                "graph_analysis": graph_result,
                "case_similarity": similarity_result
            },
            "suspicious_entities": llm_report.get("suspicious_entities", []),
            "timeline": llm_report.get("timeline", []),
            "key_findings": llm_report.get("key_findings", []),
            "recommendations": llm_report.get("recommendations", []),
            "matched_case_comment": llm_report.get("matched_case_comment", ""),
            "rag_context": {
                "relevant_cases": rag_result.get("relevant_cases", []),
                "relevant_laws": rag_result.get("relevant_laws", [])
            },
            "llm_generated": llm_report.get("generated_at", ""),
            "report_ready": True
        }
    
    def _store_report(self, case_id: str, report_data: Dict[str, Any]):
        """Store generated report in database."""
        fci = report_data.get("forensic_confidence_index", {})
        
        report = Report(
            case_id=case_id,
            summary=report_data.get("executive_summary", ""),
            timeline=report_data.get("timeline", []),
            suspicious_entities=report_data.get("suspicious_entities", []),
            risk_level=fci.get("risk_level", "Unknown"),
            confidence_score=fci.get("confidence_score", 0.0),
            matched_case_comment=report_data.get("matched_case_comment", ""),
            generated_report=__import__('json').dumps(report_data, default=str)
        )
        
        self.db.add(report)
        self.db.commit()
    
    async def run_analysis_step(self, case_id: str, step: str) -> Dict[str, Any]:
        """Run a single analysis step (for step-by-step execution)."""
        
        steps = {
            "rules": self.rule_engine.analyze,
            "anomaly": self.anomaly_detector.analyze,
            "graph": self.graph_engine.build_graph,
            "similarity": lambda cid: self.similarity_engine.compute_similarity(
                cid, self.graph_engine.build_graph(cid)
            ),
            "rag": lambda cid: self.rag_engine.retrieve_for_case({
                "case_id": cid,
                "triggered_rules": [],
                "flagged_entities": []
            }),
            "fci": lambda cid: self.fci_engine.calculate({
                "rule_analysis": self.rule_engine.analyze(cid),
                "anomaly_analysis": self.anomaly_detector.analyze(cid),
                "graph_analysis": self.graph_engine.build_graph(cid),
                "similarity_analysis": self.similarity_engine.compute_similarity(
                    cid, self.graph_engine.build_graph(cid)
                )
            })
        }
        
        if step not in steps:
            return {"error": f"Unknown step: {step}"}
        
        try:
            result = steps[step](case_id)
            return {"step": step, "result": result, "status": "success"}
        except Exception as e:
            return {"step": step, "error": str(e), "status": "failed"}
    
    def get_analysis_status(self, case_id: str) -> Dict[str, Any]:
        """Get status of case analysis."""
        case = self.db.query(Case).filter(Case.case_id == case_id).first()
        if not case:
            return {"exists": False}
        
        reports = self.db.query(Report).filter(Report.case_id == case_id).all()
        
        return {
            "exists": True,
            "case_id": case_id,
            "status": case.status,
            "fci_score": case.fci_score,
            "risk_level": case.risk_level,
            "reports_generated": len(reports),
            "created_at": case.created_at.isoformat() if case.created_at else None,
            "updated_at": case.updated_at.isoformat() if case.updated_at else None
        }