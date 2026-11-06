import json
import csv
import io
from datetime import datetime
from typing import List, Dict, Any, Optional
from dateutil import parser as date_parser
from sqlalchemy.orm import Session
from .models import Evidence, Entity
from .security import hash_string

class EvidenceIngestor:
    def __init__(self, db: Session):
        self.db = db
    
    def parse_timestamp(self, ts_value: Any) -> Optional[datetime]:
        """Parse various timestamp formats."""
        if isinstance(ts_value, datetime):
            return ts_value
        if isinstance(ts_value, (int, float)):
            # Assume Unix timestamp
            return datetime.fromtimestamp(ts_value)
        try:
            return date_parser.parse(str(ts_value))
        except (ValueError, OverflowError, TypeError):
            return datetime.utcnow()
    
    def normalize_log_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a log entry to standard format."""
        normalized = {
            "timestamp": self.parse_timestamp(entry.get("timestamp", entry.get("ts", entry.get("time", datetime.utcnow())))),
            "user": str(entry.get("user", entry.get("username", entry.get("uid", "unknown")))).lower().strip(),
            "ip_address": str(entry.get("ip", entry.get("ip_address", entry.get("source_ip", "0.0.0.0")))).strip(),
            "device": str(entry.get("device", entry.get("hostname", entry.get("host", "unknown")))),
            "file_path": str(entry.get("file", entry.get("filepath", entry.get("path", "")))),
            "action": str(entry.get("action", entry.get("event", entry.get("type", "unknown")))).lower().strip(),
            "raw_data": entry
        }
        return normalized
    
    def ingest_json(self, case_id: str, json_data: str) -> List[Evidence]:
        """Ingest JSON formatted logs."""
        data = json.loads(json_data)
        if isinstance(data, dict):
            data = [data]
        return self._ingest_entries(case_id, data)
    
    def ingest_csv(self, case_id: str, csv_data: str) -> List[Evidence]:
        """Ingest CSV formatted logs."""
        reader = csv.DictReader(io.StringIO(csv_data))
        entries = list(reader)
        return self._ingest_entries(case_id, entries)
    
    def ingest_logs(self, case_id: str, logs: List[Dict[str, Any]]) -> List[Evidence]:
        """Ingest list of log entries."""
        return self._ingest_entries(case_id, logs)
    
    def _ingest_entries(self, case_id: str, entries: List[Dict[str, Any]]) -> List[Evidence]:
        """Internal method to ingest normalized entries."""
        evidence_records = []
        
        for entry in entries:
            normalized = self.normalize_log_entry(entry)
            
            evidence = Evidence(
                case_id=case_id,
                timestamp=normalized["timestamp"],
                user=normalized["user"],
                ip_address=normalized["ip_address"],
                device=normalized["device"],
                file_path=normalized["file_path"],
                action=normalized["action"],
                raw_data=normalized["raw_data"]
            )
            
            self.db.add(evidence)
            self.db.flush()  # Get ID
            
            # Extract and store entities
            self._extract_entities(evidence, normalized)
            
            evidence_records.append(evidence)
        
        self.db.commit()
        return evidence_records
    
    def _extract_entities(self, evidence: Evidence, normalized: Dict[str, Any]):
        """Extract entities from normalized entry."""
        entities = []
        
        # User entity
        if normalized["user"] and normalized["user"] != "unknown":
            entities.append(Entity(
                evidence_id=evidence.id,
                entity_type="user",
                entity_value=normalized["user"]
            ))
        
        # IP entity
        if normalized["ip_address"] and normalized["ip_address"] != "0.0.0.0":
            entities.append(Entity(
                evidence_id=evidence.id,
                entity_type="ip",
                entity_value=normalized["ip_address"]
            ))
        
        # Device entity
        if normalized["device"] and normalized["device"] != "unknown":
            entities.append(Entity(
                evidence_id=evidence.id,
                entity_type="device",
                entity_value=normalized["device"]
            ))
        
        # File entity
        if normalized["file_path"]:
            entities.append(Entity(
                evidence_id=evidence.id,
                entity_type="file",
                entity_value=normalized["file_path"]
            ))
        
        # Process entity from action
        if normalized["action"]:
            entities.append(Entity(
                evidence_id=evidence.id,
                entity_type="process",
                entity_value=normalized["action"]
            ))
        
        for entity in entities:
            self.db.add(entity)
    
    def get_evidence_by_case(self, case_id: str) -> List[Evidence]:
        """Retrieve all evidence for a case."""
        return self.db.query(Evidence).filter(Evidence.case_id == case_id).all()