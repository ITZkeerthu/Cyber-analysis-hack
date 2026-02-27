# 🔐 Hybrid Offline Forensic Intelligence System (H.O.F.I.S.)

A comprehensive, fully offline forensic evidence ingestion and analysis platform powered by local AI.

## 📋 Overview

H.O.F.I.S. is a security-focused application that:
- **Ingests** forensic evidence securely with integrity verification
- **Analyzes** using rule-based validation and ML-powered anomaly detection
- **Visualizes** attack patterns through interactive graph reconstruction
- **Compares** with historical cases to identify patterns
- **Generates** AI-powered reports using local LLM (Mistral-7B)
- **Computes** Forensic Confidence Index (FCI) for risk assessment

## 🏗️ Architecture

```
Evidence Ingestion → Rules → Anomaly → Graph → Similarity → RAG → LLM → FCI → Report
```

### Components

| Component | Technology | Purpose |
|-----------|------------|---------|
| Backend | FastAPI + SQLite | Core API & Data Storage |
| Rule Engine | Custom Python | Security rule validation |
| Anomaly Detection | Isolation Forest | Behavioral analysis |
| Graph Engine | NetworkX | Crime reconstruction |
| Similarity | FAISS + Cosine | Case pattern matching |
| RAG | Sentence Transformers | Context retrieval |
| LLM | Ollama + Mistral-7B | Natural language reports |
| Frontend | React + Cytoscape.js | Interactive visualization |

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+
- [Ollama](https://ollama.ai/) with Mistral-7B

### 1. Clone & Setup Backend

```bash
cd cyber-hackathon/backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Install Ollama & Pull Model

```bash
# Install Ollama from https://ollama.ai/
# Then pull Mistral-7B:
ollama pull mistral

# Verify it's working:
ollama run mistral "Hello"
```

### 3. Start Backend

```bash
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`

### 4. Setup Frontend

```bash
cd frontend

# Install dependencies
npm install

# Start React app
npm start
```

The UI will open at `http://localhost:3000`

## 📊 API Endpoints

### Case Management
- `POST /cases/create` - Create new case
- `GET /cases` - List all cases
- `GET /cases/{case_id}` - Get case details

### Evidence Upload
- `POST /upload` - Upload JSON/CSV file
- `POST /upload/json` - Upload JSON logs directly
- `GET /evidence/{case_id}` - Get case evidence

### Analysis
- `POST /analyze/rules` - Rule-based analysis
- `POST /analyze/anomaly` - Anomaly detection
- `GET /graph/{case_id}` - Graph visualization data
- `POST /analyze/similarity` - Case similarity check
- `POST /retrieve` - RAG retrieval
- `POST /generate-report` - LLM report generation
- `POST /fci` - Calculate FCI score
- `POST /full-analysis` - Complete pipeline

### Reports
- `GET /report/{case_id}` - Get generated report
- `GET /status/{case_id}` - Check analysis status

## 🧪 Testing with Sample Data

```bash
# Upload sample data
curl -X POST "http://localhost:8000/upload" \
  -F "case_id=CASE-001" \
  -F "file=@sample_data/suspicious_activity.json"

# Run full analysis
curl -X POST "http://localhost:8000/full-analysis" \
  -F "case_id=CASE-001"

# Get report
curl "http://localhost:8000/report/CASE-001"
```

## 📁 Project Structure

```
cyber-hackathon/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI entry point
│   │   ├── config.py            # Configuration
│   │   ├── database.py          # Database setup
│   │   ├── models.py            # SQLAlchemy models
│   │   ├── schemas.py           # Pydantic schemas
│   │   ├── security.py          # Security utilities
│   │   ├── hashing.py           # File hashing
│   │   ├── ingestion.py         # Evidence ingestion
│   │   ├── rule_engine.py       # Rule-based analysis
│   │   ├── anomaly_detection.py # Anomaly detection
│   │   ├── graph_engine.py      # Graph construction
│   │   ├── case_similarity.py  # Similarity search
│   │   ├── rag_engine.py        # RAG retrieval
│   │   ├── llm_engine.py        # Local LLM integration
│   │   ├── fci_engine.py        # FCI calculation
│   │   └── orchestrator.py      # Analysis pipeline
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.js               # Main component
│   │   ├── components/
│   │   │   ├── UploadEvidence.js
│   │   │   ├── GraphView.js
│   │   │   ├── ReportView.js
│   │   │   └── SimilarityAlert.js
│   │   └── index.css
│   └── package.json
└── sample_data/
    ├── suspicious_activity.json
    └── sample_logs.csv
```

## 🔧 Configuration

Edit `/backend/app/config.py` to customize:

```python
# LLM Model
LLM_MODEL = "mistral"  # Change to your preferred model

# FCI Weights
FCI_WEIGHTS = {
    "rule_score": 0.30,
    "anomaly_score": 0.25,
    "centrality_score": 0.20,
    "similarity_score": 0.15,
    "evidence_consistency": 0.10
}

# Rule Thresholds
RULE_THRESHOLDS = {
    "failed_login_count": 5,
    "failed_login_window_minutes": 2,
    "business_hours_start": 9,
    "business_hours_end": 18,
    "multi_ip_threshold": 3
}
```

## 📊 Forensic Confidence Index (FCI)

The FCI scores the overall risk:
- **High (≥0.7)**: Strong evidence of security incident
- **Medium (0.4-0.69)**: Potential concerns warranting review
- **Low (<0.4)**: Limited suspicious activity

Components:
1. **Rule Score** (30%): Triggered security rules
2. **Anomaly Score** (25%): Behavioral deviations
3. **Centrality Score** (20%): Graph node importance
4. **Similarity Score** (15%): Historical case matches
5. **Evidence Consistency** (10%): Cross-validation

## 🛡️ Security Features

- ✅ SHA-256 file integrity hashing
- ✅ No external API dependencies
- ✅ Fully offline operation
- ✅ Secure evidence storage
- ✅ Anonymous IP handling option

## 🐛 Troubleshooting

### Ollama Connection Error
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# If not running, start Ollama:
ollama serve
```

### FAISS Import Error
```bash
# On some systems, install via conda:
conda install -c conda-forge faiss-cpu

# Or use pre-built wheel:
pip install faiss-cpu --no-cache-dir
```

### React Build Issues
```bash
cd frontend
rm -rf node_modules package-lock.json
npm install
```

## 📚 Data Format

### JSON Evidence Format
```json
[
  {
    "timestamp": "2024-01-15T09:30:00",
    "user": "john.doe",
    "ip": "192.168.1.100",
    "device": "workstation-01",
    "file": "/data/sensitive.txt",
    "action": "access"
  }
]
```

### CSV Evidence Format
```csv
timestamp,user,ip,device,file,action
2024-01-15T09:30:00,john.doe,192.168.1.100,workstation-01,/data/sensitive.txt,access
```

## 📄 License

MIT License - Free for forensic and research use.

---

**Note**: This system is designed for forensic analysis of your own systems. Ensure compliance with applicable laws and regulations.