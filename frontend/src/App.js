import React, { useState, useEffect } from 'react';
import UploadEvidence from './components/UploadEvidence';
import GraphView from './components/GraphView';
import ReportView from './components/ReportView';
import SimilarityAlert from './components/SimilarityAlert';
import './App.css';

const API_BASE = 'http://localhost:8000';

function App() {
  const [cases, setCases] = useState([]);
  const [selectedCase, setSelectedCase] = useState(null);
  const [caseData, setCaseData] = useState(null);
  const [analysisData, setAnalysisData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('upload');
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchCases();
  }, []);

  useEffect(() => {
    if (selectedCase) {
      fetchCaseData(selectedCase);
    }
  }, [selectedCase]);

  const fetchCases = async () => {
    try {
      const response = await fetch(`${API_BASE}/cases`);
      const data = await response.json();
      setCases(data);
    } catch (err) {
      console.error('Failed to fetch cases:', err);
    }
  };

  const fetchCaseData = async (caseId) => {
    try {
      const response = await fetch(`${API_BASE}/cases/${caseId}`);
      const data = await response.json();
      setCaseData(data);
      setError(null);
    } catch (err) {
      setError('Failed to fetch case data');
    }
  };

  const createCase = async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    
    try {
      const response = await fetch(`${API_BASE}/cases/create`, {
        method: 'POST',
        body: formData
      });
      const data = await response.json();
      await fetchCases();
      setSelectedCase(data.case_id);
      e.target.reset();
    } catch (err) {
      setError('Failed to create case');
    }
  };

  const runFullAnalysis = async () => {
    if (!selectedCase) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch(`${API_BASE}/full-analysis`, {
        method: 'POST',
        body: new URLSearchParams({ case_id: selectedCase })
      });
      const data = await response.json();
      setAnalysisData(data);
      setReport(data);
      await fetchCaseData(selectedCase);
    } catch (err) {
      setError('Analysis failed: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const renderFCI = () => {
    if (!report?.forensic_confidence_index) return null;
    
    const fci = report.forensic_confidence_index;
    const getColor = (risk) => {
      if (risk === 'High') return '#ff4444';
      if (risk === 'Medium') return '#ffaa00';
      return '#44ff44';
    };

    return (
      <div className="fci-card">
        <h3>🔍 Forensic Confidence Index</h3>
        <div className="fci-score" style={{ color: getColor(fci.risk_level) }}>
          <span className="score-value">{(fci.confidence_score * 100).toFixed(1)}%</span>
          <span className="risk-level">{fci.risk_level} Risk</span>
        </div>
        <div className="fci-components">
          {Object.entries(fci.component_scores || {}).map(([key, value]) => (
            <div key={key} className="component-bar">
              <div className="component-label">{key.replace(/_/g, ' ')}</div>
              <div className="component-progress">
                <div 
                  className="component-fill" 
                  style={{ width: `${value * 100}%` }}
                />
              </div>
              <div className="component-value">{(value * 100).toFixed(1)}%</div>
            </div>
          ))}
        </div>
      </div>
    );
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1>🔐 Hybrid Offline Forensic Intelligence System</h1>
        <p>Secure Evidence Ingestion & Analysis Platform</p>
      </header>

      <div className="main-container">
        <div className="sidebar">
          <section className="section">
            <h3>🆕 Create Case</h3>
            <form onSubmit={createCase}>
              <input 
                type="text" 
                name="title" 
                placeholder="Case Title" 
                required 
              />
              <textarea 
                name="description" 
                placeholder="Case Description"
                rows="3"
              ></textarea>
              <button type="submit">Create Case</button>
            </form>
          </section>

          <section className="section">
            <h3>📁 Cases</h3>
            <select 
              value={selectedCase || ''} 
              onChange={(e) => setSelectedCase(e.target.value)}
            >
              <option value="">Select a case...</option>
              {cases.map(c => (
                <option key={c.case_id} value={c.case_id}>
                  {c.case_id} - {c.title} ({c.risk_level || 'No analysis'})
                </option>
              ))}
            </select>
          </section>

          {caseData && (
            <section className="section case-info">
              <h3>📋 Case Info</h3>
              <p><strong>ID:</strong> {caseData.case_id}</p>
              <p><strong>Title:</strong> {caseData.title}</p>
              <p><strong>Status:</strong> {caseData.status}</p>
              <p><strong>Risk Level:</strong> 
                <span className={`status-${(caseData.risk_level || 'low').toLowerCase()}`}>
                  {caseData.risk_level || 'Not analyzed'}
                </span>
              </p>
              {caseData.fci_score && (
                <p><strong>FCI Score:</strong> {(caseData.fci_score * 100).toFixed(1)}%</p>
              )}
            </section>
          )}

          {selectedCase && (
            <section className="section">
              <button 
                className="analyze-btn"
                onClick={runFullAnalysis}
                disabled={loading}
              >
                {loading ? '🔍 Analyzing...' : '🚀 Run Full Analysis'}
              </button>
            </section>
          )}

          {/* Display FCI Card */}
          {report && renderFCI()}

          {/* Similarity Alert */}
          {report?.findings?.case_similarity && (
            <SimilarityAlert similarity={report.findings.case_similarity} />
          )}
        </div>

        <div className="content">
          {error && (
            <div className="error-banner">
              ⚠️ {error}
            </div>
          )}

          {selectedCase ? (
            <>
              <div className="tabs">
                <button 
                  className={activeTab === 'upload' ? 'active' : ''}
                  onClick={() => setActiveTab('upload')}
                >
                  📤 Upload Evidence
                </button>
                <button 
                  className={activeTab === 'graph' ? 'active' : ''}
                  onClick={() => setActiveTab('graph')}
                  disabled={!report}
                >
                  🕸️ Graph View
                </button>
                <button 
                  className={activeTab === 'report' ? 'active' : ''}
                  onClick={() => setActiveTab('report')}
                  disabled={!report}
                >
                  📊 Report
                </button>
              </div>

              <div className="tab-content">
                {activeTab === 'upload' && (
                  <UploadEvidence caseId={selectedCase} onUpload={fetchCaseData} />
                )}
                
                {activeTab === 'graph' && report && (
                  <GraphView graphData={report.findings?.graph_analysis} />
                )}
                
                {activeTab === 'report' && report &> (
                  <ReportView report={report} />
                )}
              </div>
            </>
          ) : (
            <div className="welcome">
              <h2>Welcome to H.O.F.I.S.</h2>
              <p>Create a new case or select an existing one to begin analysis.</p>
              <div className="features">
                <div className="feature">
                  <span>🔐</span>
                  <h4>Secure</h4>
                  <p>Fully offline operation</p>
                </div>
                <div className="feature">
                  <span>🤖</span>
                  <h4>AI-Powered</h4>
                  <p>Local LLM reasoning</p>
                </div>
                <div className="feature">
                  <span>📊</span>
                  <h4>Intelligent</h4>
                  <p>Graph-based analysis</p>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;