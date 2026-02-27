import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

DATABASE_URL = f"sqlite:///{DATA_DIR}/forensics.db"
VECTOR_STORE_PATH = str(DATA_DIR / "faiss_index")
CASE_SUMMARIES_DIR = DATA_DIR / "case_summaries"
CASE_SUMMARIES_DIR.mkdir(exist_ok=True)
CYBER_LAW_DIR = DATA_DIR / "cyber_law"
CYBER_LAW_DIR.mkdir(exist_ok=True)

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
LLM_MODEL = os.getenv("LLM_MODEL", "mistral")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")

FCI_WEIGHTS = {
    "rule_score": 0.30,
    "anomaly_score": 0.25,
    "centrality_score": 0.20,
    "similarity_score": 0.15,
    "evidence_consistency": 0.10
}

RULE_THRESHOLDS = {
    "failed_login_count": 5,
    "failed_login_window_minutes": 2,
    "business_hours_start": 9,
    "business_hours_end": 18,
    "multi_ip_threshold": 3
}

SIMILARITY_THRESHOLD = 0.75