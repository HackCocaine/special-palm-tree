/**
 * RecommendationsPanel - Actionable Mitigation Recommendations
 * Slide-out panel with prioritized security actions
 */

import React from 'react';
import './cti-dashboard.css';

interface RecommendationsPanelProps {
  isOpen: boolean;
  onClose: () => void;
  recommendations: {
    immediate: string[];
    strategic: string[];
    rationale?: Record<string, string>;
  };
}

const RecommendationsPanel: React.FC<RecommendationsPanelProps> = ({
  isOpen,
  onClose,
  recommendations
}) => {
  if (!isOpen) return null;

  return (
    <div className="cti-overlay-panel open">
      <div className="cti-recommendations-header">
        <div className="cti-recommendations-title">
          <span className="cti-overlay-icon">🛡️</span>
          <h2>Mitigation Actions</h2>
        </div>
        <button className="cti-overlay-close" onClick={onClose}>
          ✕
        </button>
      </div>

      <div className="cti-recommendations-content">
        {/* Immediate Actions */}
        <div className="cti-recommendation-group">
          <h3 className="cti-recommendation-group-title immediate">
            <span>🔴</span>
            Immediate Actions
          </h3>
          {recommendations.immediate.map((action, i) => (
            <div key={i} className="cti-recommendation-item immediate">
              <p className="cti-recommendation-text">{action}</p>
              {recommendations.rationale && recommendations.rationale[action] && (
                <div className="cti-recommendation-why">
                  <div className="cti-recommendation-why-title">Why this matters</div>
                  <p className="cti-recommendation-why-text">
                    {recommendations.rationale[action]}
                  </p>
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Strategic Recommendations */}
        <div className="cti-recommendation-group">
          <h3 className="cti-recommendation-group-title strategic">
            <span>🔵</span>
            Strategic Recommendations
          </h3>
          {recommendations.strategic.map((action, i) => (
            <div key={i} className="cti-recommendation-item strategic">
              <p className="cti-recommendation-text">{action}</p>
              {recommendations.rationale && recommendations.rationale[action] && (
                <div className="cti-recommendation-why">
                  <div className="cti-recommendation-why-title">Why this matters</div>
                  <p className="cti-recommendation-why-text">
                    {recommendations.rationale[action]}
                  </p>
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Quick Reference */}
        <div className="cti-recommendation-group">
          <h3 className="cti-recommendation-group-title">
            <span>📋</span>
            Priority Reference
          </h3>
          <div className="cti-priority-legend">
            <div className="cti-priority-item">
              <span className="cti-priority-badge critical">P1</span>
              <span className="cti-priority-desc">Critical - Address within 24h</span>
            </div>
            <div className="cti-priority-item">
              <span className="cti-priority-badge high">P2</span>
              <span className="cti-priority-desc">High - Address within 72h</span>
            </div>
            <div className="cti-priority-item">
              <span className="cti-priority-badge medium">P3</span>
              <span className="cti-priority-desc">Medium - Address within 1 week</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default RecommendationsPanel;
