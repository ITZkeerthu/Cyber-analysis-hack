from sqlalchemy import Column, Integer, String, Float, DateTime, Text, ForeignKey, JSON, LargeBinary
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base

class Evidence(Base):
    __tablename__ = "evidence"
    
    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String, index=True)
    timestamp = Column(DateTime)
    user = Column(String, index=True)
    ip_address = Column(String)
    device = Column(String)
    file_path = Column(String)
    action = Column(String, index=True)
    raw_data = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    entities = relationship("Entity", back_populates="evidence")

class Entity(Base):
    __tablename__ = "entities"
    
    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(Integer, ForeignKey("evidence.id"))
    entity_type = Column(String)  # user, file, device, ip, process
    entity_value = Column(String)
    risk_score = Column(Float, default=0.0)
    
    evidence = relationship("Evidence", back_populates="entities")

class Case(Base):
    __tablename__ = "cases"
    
    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String, unique=True, index=True)
    title = Column(String)
    description = Column(Text)
    status = Column(String, default="open")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    fci_score = Column(Float)
    risk_level = Column(String)

class CaseGraph(Base):
    __tablename__ = "case_graphs"
    
    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String, ForeignKey("cases.case_id"))
    graph_data = Column(JSON)  # Serialized graph
    feature_vector = Column(JSON)  # For similarity comparison
    created_at = Column(DateTime, default=datetime.utcnow)

class Report(Base):
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String, ForeignKey("cases.case_id"))
    summary = Column(Text)
    timeline = Column(JSON)
    suspicious_entities = Column(JSON)
    risk_level = Column(String)
    confidence_score = Column(Float)
    matched_case_comment = Column(String)
    generated_report = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)