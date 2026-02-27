import React from 'react';
import './SimilarityAlert.css';

function SimilarityAlert({ similarity }) {
  if (!similarity) return null;

  const { matched_case_id, similarity_score, similar_cases } = similarity;

  // Only show if there's a significant match
  if (!matched_case_id || similarity_score < 0.75) {
    return null;
  }

  const getSimilarityColor = (score) => {
    if (score >= 0.9) return '#ff4444';
    if (score >= 0.8) return '#ffaa00';
    return '#44ff44';
  };

  return (
    <div className="similarity-alert">
      <div className="alert-header">
        <span className="alert-icon">⚠️</span>
        <span className="alert-title">Similar Case Detected</span>
      </div>

      <div className="alert-content">
        <div className="match-info">
          <div className="match-case">
            <span className="label">Matched Case:</span>
            <span className="value case-id">{matched_case_id}</span>
          </div>

          <div className="match-score">
            <span className="label">Similarity:</span>
            <span 
              className="value score"
              style={{ color: getSimilarityColor(similarity_score) }}
            >
              {(similarity_score * 100).toFixed(1)}%
            </span>
          </div>
        </div>

        {similar_cases?.length > 1 && (
          <div className="related-cases">
            <strong>Related Cases:</strong>
            <ul>
              {similar_cases.slice(1, 4).map((c, i) => (
                <li key={i}>
                  {c.case_id} ({(c.similarity_score * 100).toFixed(1)}%)
                  {c.risk_level && (
                    <span className={`risk-tag ${c.risk_level.toLowerCase()}`}>
                      {c.risk_level}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}

        <div className="alert-message">
          This case shows patterns similar to previous incidents. 
          Consider reviewing the matched case for additional context 
          and potential indicators of compromise.
        </div>
      </div>
    </div>
  );
}

export default SimilarityAlert;