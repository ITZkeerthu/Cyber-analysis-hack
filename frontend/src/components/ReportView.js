import React, { useState } from 'react';
import './ReportView.css';

function ReportView({ report }) {
  const [activeSection, setActiveSection] = useState('summary');

  if (!report) {
    return (
      <div className="report-view">
        <div className="no-data">
          <h3>📊 Analysis Report</h3>
          <p>No report available.</p>
          <p>Run full analysis to generate report.</p>
        </div>
      </div>
    );
  }

  const { 
    executive_summary,
    forensic_confidence_index,
    risk_assessment,
    findings,
    suspicious_entities,
    timeline,
    key_findings,
    recommendations,
    matched_case_comment,
    rag_context
  } = report;

  const fci = forensic_confidence_index || {};

  const renderSummary = () => (
    <div className="report-section">
      <h4>📋 Executive Summary</h4>
      <div className="summary-box">
        <p>{executive_summary || 'No summary available.'}</p>
      </div>
      
      {risk_assessment && (
        <div className="risk-box">
          <h5>Risk Assessment</h5>
          <div className={`risk-badge ${risk_assessment.level?.toLowerCase()}`}>
            {risk_assessment.level} RISK
          </div>
          <p className="risk-interpretation">{fci.interpretation}</p>
        </div>
      )}
    </div>
  );

  const renderFindings = () => (
    <div className="report-section">
      <h4>🔍 Key Findings</h4>
      
      {findings?.rule_based?.triggered_rules?.length > 0 && (
        <div className="finding-group">
          <h5>⚠️ Rule Violations</h5>
          <ul>
            {findings.rule_based.triggered_rules.map((rule, i) => (
              <li key={i}>{rule.replace(/_/g, ' ').toUpperCase()}</li>
            ))}
          </ul>
        </div>
      )}

      {findings?.anomaly_detection?.flagged_users?.length > 0 && (
        <div className="finding-group">
          <h5>👤 Anomalous Users</h5>
          <div className="user-list">
            {findings.anomaly_detection.flagged_users.map((user, i) => {
              const score = findings.anomaly_detection.anomaly_scores?.[user] || 0;
              return (
                <div key={i} className="user-item">
                  <span className="user-name">{user}</span>
                  <span className="user-score">
                    {(score * 100).toFixed(1)}%
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {findings?.graph_analysis?.central_nodes?.length > 0 && (
        <div className="finding-group">
          <h5>🕸️ Central Suspicious Nodes</h5>
          <table className="nodes-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Label</th>
                <th>Risk Score</th>
              </tr>
            </thead>
            <tbody>
              {findings.graph_analysis.central_nodes.map((node, i) => (
                <tr key={i}>
                  <td>{node.type}</td>
                  <td>{node.label}</td>
                  <td><span className={`risk-${Math.floor(node.risk_score * 3)}`}>
                    {(node.risk_score * 100).toFixed(1)}%
                  </span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );

  const renderTimeline = () => (
    <div className="report-section">
      <h4>⏱️ Event Timeline</h4>
      
      {timeline?.length > 0 ? (
        <div className="timeline">
          {timeline.map((event, i) => (
            <div key={i} className="timeline-item">
              <div className={`timeline-dot severity-${event.severity?.toLowerCase()}`}></div>
              <div className="timeline-content">
                <div className="timeline-time">{event.time}</div>
                <div className="timeline-event">{event.event}</div>
                {event.severity && (
                  <span className={`severity-badge ${event.severity.toLowerCase()}`}>
                    {event.severity}
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <p className="no-data-text">No timeline events recorded.</p>
      )}
    </div>
  );

  const renderEntities = () => (
    <div className="report-section">
      <h4>🚩 Suspicious Entities</h4>
      
      {suspicious_entities?.length > 0 ? (
        <div className="entities-list">
          {suspicious_entities.map((entity, i) => (
            <div key={i} className="entity-card">
              <div className="entity-header">
                <span className={`entity-type type-${entity.type}`}>
                  {entity.type?.toUpperCase()}
                </span>
                <span className="entity-name">{entity.entity}</span>
              </div>
              
              {entity.risk_factors?.length > 0 && (
                <div className="risk-factors">
                  <strong>Risk Factors:</strong>
                  <ul>
                    {entity.risk_factors.map((factor, j) => (
                      <li key={j}>{factor}</li>
                    ))}
                  </ul>
                </div>
              )}
              
              {entity.recommendation && (
                <div className="recommendation">
                  <strong>Recommendation:</strong> {entity.recommendation}
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <p className="no-data-text">No suspicious entities identified.</p>
      )}
    </div>
  );

  const renderRecommendations = () => (
    <div className="report-section">
      <h4>💡 Recommendations</h4>
      
      {recommendations?.length > 0 ? (
        <ol className="recommendations-list">
          {recommendations.map((rec, i) => (
            <li key={i}>{rec}</li>
          ))}
        </ol>
      ) : (
        <div className="default-recommendations">
          <ol>
            <li>Review flagged entities for further investigation</li>
            <li>Monitor anomalous users for ongoing behavior</li>
            <li>Check system logs for additional context</li>
            <li>Consider implementing additional security controls</li>
          </ol>
        </div>
      )}
    </div>
  );

  const renderRelatedCases = () => (
    <div className="report-section">
      <h4>🔗 Related Cases & Legal Context</h4>
      
      {matched_case_comment && (
        <div className="case-comment">
          <strong>Similar Case Analysis:</strong>
          <p>{matched_case_comment}</p>
        </div>
      )}

      {rag_context?.relevant_cases?.length > 0 && (
        <div className="related-cases">
          <h5>Similar Cases</h5>
          {rag_context.relevant_cases.map((c, i) => (
            <div key={i} className="case-item">
              <div className="case-header">
                <span className="case-source">{c.source}</span>
                <span className="case-score">Score: {(c.relevance_score * 100).toFixed(1)}%</span>
              </div>
              <p className="case-preview">{c.content?.substring(0, 200)}...</p>
            </div>
          ))}
        </div>
      )}

      {rag_context?.relevant_laws?.length > 0 && (
        <div className="related-laws">
          <h5>Applicable Regulations</h5>
          {rag_context.relevant_laws.map((law, i) => (
            <div key={i} className="law-item">
              <div className="law-source">{law.source}</div>
              <p>{law.content?.substring(0, 200)}...</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );

  const sections = [
    { id: 'summary', label: '📋 Summary' },
    { id: 'findings', label: '🔍 Findings' },
    { id: 'timeline', label: '⏱️ Timeline' },
    { id: 'entities', label: '🚩 Entities' },
    { id: 'recommendations', label: '💡 Actions' },
    { id: 'related', label: '🔗 Related' }
  ];

  return (
    <div className="report-view">
      <div className="report-header">
        <h3>📊 Forensic Analysis Report</h3>
        <div className="report-meta">
          <span>Case: {report.case_id}</span>
          <span>Generated: {new Date(report.analysis_timestamp).toLocaleString()}</span>
        </div>
      </div>

      <div className="report-nav">
        {sections.map(section => (
          <button
            key={section.id}
            className={activeSection === section.id ? 'active' : ''}
            onClick={() => setActiveSection(section.id)}
          >
            {section.label}
          </button>
        ))}
      </div>

      <div className="report-content">
        {activeSection === 'summary' && renderSummary()}
        {activeSection === 'findings' && renderFindings()}
        {activeSection === 'timeline' && renderTimeline()}
        {activeSection === 'entities' && renderEntities()}
        {activeSection === 'recommendations' && renderRecommendations()}
        {activeSection === 'related' && renderRelatedCases()}
      </div>
    </div>
  );
}

export default ReportView;