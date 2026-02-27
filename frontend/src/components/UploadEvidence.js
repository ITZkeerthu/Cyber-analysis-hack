import React, { useState } from 'react';
import './UploadEvidence.css';

const API_BASE = 'http://localhost:8000';

function UploadEvidence({ caseId, onUpload }) {
  const [file, setFile] = useState(null);
  const [jsonInput, setJsonInput] = useState('');
  const [uploadMode, setUploadMode] = useState('file');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState(null);
  const [evidenceCount, setEvidenceCount] = useState(0);

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
    setMessage(null);
  };

  const handleFileUpload = async (e) => {
    e.preventDefault();
    if (!file) return;

    setLoading(true);
    setMessage(null);

    const formData = new FormData();
    formData.append('case_id', caseId);
    formData.append('file', file);

    try {
      const response = await fetch(`${API_BASE}/upload`, {
        method: 'POST',
        body: formData
      });

      const data = await response.json();

      if (response.ok) {
        setMessage({ type: 'success', text: `Uploaded ${data.records_ingested} records successfully!` });
        setEvidenceCount(prev => prev + data.records_ingested);
        setFile(null);
        onUpload?.();
      } else {
        setMessage({ type: 'error', text: data.detail || 'Upload failed' });
      }
    } catch (err) {
      setMessage({ type: 'error', text: 'Network error: ' + err.message });
    } finally {
      setLoading(false);
    }
  };

  const handleJsonUpload = async (e) => {
    e.preventDefault();
    if (!jsonInput.trim()) return;

    setLoading(true);
    setMessage(null);

    try {
      const logs = JSON.parse(jsonInput);
      const payload = {
        case_id: caseId,
        logs: Array.isArray(logs) ? logs : [logs]
      };

      const response = await fetch(`${API_BASE}/upload/json`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      const data = await response.json();

      if (response.ok) {
        setMessage({ type: 'success', text: `Uploaded ${data.records_ingested} records successfully!` });
        setEvidenceCount(prev => prev + data.records_ingested);
        setJsonInput('');
        onUpload?.();
      } else {
        setMessage({ type: 'error', text: data.detail || 'Upload failed' });
      }
    } catch (err) {
      setMessage({ type: 'error', text: 'Invalid JSON: ' + err.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="upload-evidence">
      <h3>📤 Upload Evidence</h3>

      <div className="upload-mode-toggle">
        <button
          className={uploadMode === 'file' ? 'active' : ''}
          onClick={() => setUploadMode('file')}
        >
          File Upload
        </button>
        <button
          className={uploadMode === 'json' ? 'active' : ''}
          onClick={() => setUploadMode('json')}
        >
          JSON Input
        </button>
      </div>

      {message && (
        <div className={`message ${message.type}`}>
          {message.text}
        </div>
      )}

      {uploadMode === 'file' ? (
        <form onSubmit={handleFileUpload}>
          <div className="file-drop">
            <input
              type="file"
              accept=".json,.csv"
              onChange={handleFileChange}
              id="file-input"
            />
            <label htmlFor="file-input">
              {file ? file.name : 'Click to select or drag file here'}
            </label>
          </div>

          <div className="format-hint">
            <p><strong>Supported formats:</strong></p>
            <ul>
              <li><code>.json</code> - JSON array of log entries</li>
              <li><code>.csv</code> - Comma-separated values</li>
            </ul>
          </div>

          <button
            type="submit"
            disabled={!file || loading}
            className="upload-btn"
          >
            {loading ? 'Uploading...' : '📤 Upload File'}
          </button>
        </form>
      ) : (
        <form onSubmit={handleJsonUpload}>
          <textarea
            value={jsonInput}
            onChange={(e) => setJsonInput(e.target.value)}
            placeholder={`[\n  {\n    "timestamp": "2024-01-15T09:30:00",\n    "user": "john.doe",\n    "ip": "192.168.1.100",\n    "device": "workstation-01",\n    "file": "/sensitive/data.xlsx",\n    "action": "access"\n  }\n]`}
            rows={15}
          />

          <button
            type="submit"
            disabled={!jsonInput.trim() || loading}
            className="upload-btn"
          >
            {loading ? 'Uploading...' : '📤 Upload JSON'}
          </button>
        </form>
      )}

      {evidenceCount > 0 && (
        <div className="evidence-summary">
          <p>📊 Total evidence in this case: <strong>{evidenceCount}</strong> records</p>
        </div>
      )}
    </div>
  );
}

export default UploadEvidence;