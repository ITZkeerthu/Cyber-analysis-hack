import os
import json
import faiss
import numpy as np
from typing import List, Dict, Any, Optional
from sentence_transformers import SentenceTransformer
from pathlib import Path
from .config import VECTOR_STORE_PATH, CASE_SUMMARIES_DIR, CYBER_LAW_DIR, EMBEDDING_MODEL

class RAGEngine:
    def __init__(self):
        self.model = SentenceTransformer(EMBEDDING_MODEL)
        self.dimension = self.model.get_sentence_embedding_dimension()
        self.index = None
        self.documents = []
        self.vector_store_path = VECTOR_STORE_PATH
        self._load_or_create_index()
    
    def _load_or_create_index(self):
        """Load existing FAISS index or create new one."""
        index_file = f"{self.vector_store_path}.index"
        docs_file = f"{self.vector_store_path}.json"
        
        if os.path.exists(index_file) and os.path.exists(docs_file):
            self.index = faiss.read_index(index_file)
            with open(docs_file, 'r') as f:
                self.documents = json.load(f)
        else:
            self.index = faiss.IndexFlatIP(self.dimension)  # Inner product for cosine similarity
            self.documents = []
            self._load_reference_documents()
    
    def _load_reference_documents(self):
        """Load case summaries and cyber law docs into the index."""
        all_docs = []
        
        # Load case summaries
        if CASE_SUMMARIES_DIR.exists():
            for file_path in CASE_SUMMARIES_DIR.glob("*.txt"):
                with open(file_path, 'r') as f:
                    content = f.read()
                    all_docs.append({
                        "type": "case_summary",
                        "source": file_path.name,
                        "content": content
                    })
        
        # Load cyber law references
        if CYBER_LAW_DIR.exists():
            for file_path in CYBER_LAW_DIR.glob("*.txt"):
                with open(file_path, 'r') as f:
                    content = f.read()
                    all_docs.append({
                        "type": "cyber_law",
                        "source": file_path.name,
                        "content": content
                    })
        
        # Default documents if none exist
        if not all_docs:
            all_docs = self._get_default_documents()
        
        # Add to index
        for doc in all_docs:
            self.add_document(doc)
    
    def _get_default_documents(self) -> List[Dict[str, Any]]:
        """Get default reference documents."""
        return [
            {
                "type": "cyber_law",
                "source": "unauthorized_access.txt",
                "content": """Unauthorized Access: Accessing a computer system without permission 
                is a criminal offense. Penalties include fines and imprisonment. Key indicators 
                include: multiple failed login attempts, access from unusual locations, use of 
                stolen credentials, and bypassing security controls."""
            },
            {
                "type": "cyber_law",
                "source": "data_exfiltration.txt",
                "content": """Data Exfiltration: Unauthorized transfer of data from a computer 
                system. Common methods: USB devices, cloud uploads, email attachments, and 
                encrypted tunnels. Detection indicators: large data transfers, off-hours activity, 
                access to sensitive files, and unusual network destinations."""
            },
            {
                "type": "case_pattern",
                "source": "insider_threat.txt",
                "content": """Insider Threat Pattern: Employees with privileged access abusing 
                their position. Indicators: accessing files outside job scope, off-hours access, 
                copying data to personal devices, searching for resignation information."""
            },
            {
                "type": "case_pattern",
                "source": "lateral_movement.txt",
                "content": """Lateral Movement Pattern: Attackers moving through network after 
                initial compromise. Indicators: same credentials used on multiple systems, 
                remote desktop connections between servers, unusual administrative tool usage, 
                and credential dumping attempts."""
            },
            {
                "type": "cyber_law",
                "source": "computer_fraud.txt",
                "content": """Computer Fraud and Abuse Act: Prohibits unauthorized access to 
                protected computers, trafficking in passwords, and extortion involving computers. 
                Violations can result in both criminal and civil penalties."""
            }
        ]
    
    def add_document(self, document: Dict[str, Any]):
        """Add a document to the vector store."""
        embedding = self.model.encode(document["content"])
        
        # Normalize for cosine similarity
        embedding = embedding / np.linalg.norm(embedding)
        
        self.index.add(np.array([embedding]).astype('float32'))
        self.documents.append(document)
    
    def save_index(self):
        """Save the FAISS index to disk."""
        os.makedirs(os.path.dirname(self.vector_store_path) or '.', exist_ok=True)
        faiss.write_index(self.index, f"{self.vector_store_path}.index")
        with open(f"{self.vector_store_path}.json", 'w') as f:
            json.dump(self.documents, f)
    
    def retrieve(self, query: str, top_k: int = 5) -> Dict[str, Any]:
        """Retrieve relevant documents for a query."""
        query_embedding = self.model.encode(query)
        query_embedding = query_embedding / np.linalg.norm(query_embedding)
        
        # Search
        scores, indices = self.index.search(
            np.array([query_embedding]).astype('float32'),
            min(top_k, len(self.documents))
        )
        
        relevant_cases = []
        relevant_laws = []
        context_parts = []
        
        for score, idx in zip(scores[0], indices[0]):
            if idx >= 0 and idx < len(self.documents):
                doc = self.documents[idx]
                result = {
                    "source": doc["source"],
                    "type": doc["type"],
                    "relevance_score": round(float(score), 4),
                    "content": doc["content"][:500] + "..." if len(doc["content"]) > 500 else doc["content"]
                }
                
                if doc["type"] == "case_summary" or doc["type"] == "case_pattern":
                    relevant_cases.append(result)
                else:
                    relevant_laws.append(result)
                
                context_parts.append(f"[{doc['type']}] {doc['source']}: {doc['content']}")
        
        return {
            "relevant_cases": relevant_cases,
            "relevant_laws": relevant_laws,
            "context": "\n\n".join(context_parts[:3])  # Top 3 for context
        }
    
    def retrieve_for_case(self, case_data: Dict[str, Any]) -> Dict[str, Any]:
        """Build retrieval query from case data."""
        # Build query from suspicious entities and actions
        query_parts = []
        
        if "flagged_entities" in case_data:
            for entity in case_data["flagged_entities"]:
                query_parts.append(f"{entity.get('type')}: {entity.get('value')}")
        
        if "triggered_rules" in case_data:
            query_parts.extend(case_data["triggered_rules"])
        
        if "anomaly_scores" in case_data:
            # Add anomalous users
            for user, score in case_data["anomaly_scores"].items():
                if score > 0.5:
                    query_parts.append(f"user anomaly {user}")
        
        query = "; ".join(query_parts) if query_parts else "forensic incident investigation"
        
        return self.retrieve(query)