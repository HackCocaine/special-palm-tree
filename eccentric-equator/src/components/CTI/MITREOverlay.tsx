/**
 * MITREOverlay - MITRE ATT&CK Matrix with Mitigations
 * Slide-out panel showing TTPs and mitigation recommendations
 */

import React from 'react';
import './cti-dashboard.css';

interface MITREOverlayProps {
  isOpen: boolean;
  onClose: () => void;
  mitreAttack?: Array<{
    tactic: string;
    techniques: string[];
    mitigations: string[];
  }>;
  ttps?: Array<{
    technique: string;
    techniqueId: string;
    tactic: string;
    evidence: string;
    confidence: number;
  }>;
}

const MITREOverlay: React.FC<MITREOverlayProps> = ({
  isOpen,
  onClose,
  mitreAttack,
  ttps
}) => {
  if (!isOpen) return null;

  return (
    <div className="cti-overlay-panel open">
      {/* Header */}
      <div className="cti-overlay-header">
        <div className="cti-overlay-title">
          <span className="cti-overlay-icon">🎯</span>
          <h2>MITRE ATT&CK Matrix</h2>
        </div>
        <button className="cti-overlay-close" onClick={onClose}>
          ✕
        </button>
      </div>

      {/* Tactic Matrix Grid */}
      <div className="cti-mitre-content">
        {/* Kill Chain Phases */}
        <div className="cti-mitre-section">
          <h3 className="cti-section-title">
            <span className="cti-section-icon">⚔️</span>
            Attack Lifecycle
          </h3>
          <div className="cti-mitre-matrix">
            {mitreAttack?.map((item, i) => (
              <div key={i} className="cti-mitre-cell">
                <div className="cti-mitre-tactic">{item.tactic}</div>
                <div className="cti-mitre-techniques">
                  {item.techniques.slice(0, 3).join(', ')}
                  {item.techniques.length > 3 && ` +${item.techniques.length - 3}`}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Observed TTPs */}
        {ttps && ttps.length > 0 && (
          <div className="cti-mitre-section">
            <h3 className="cti-section-title">
              <span className="cti-section-icon">🔍</span>
              Observed TTPs
            </h3>
            <div className="cti-ttps-list">
              {ttps.map((ttp, i) => (
                <div key={i} className="cti-ttp-card">
                  <div className="cti-ttp-header">
                    <a
                      href={`https://attack.mitre.org/techniques/${ttp.techniqueId}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="cti-ttp-id"
                    >
                      {ttp.techniqueId}
                    </a>
                    <span className="cti-ttp-confidence">
                      {ttp.confidence}% confident
                    </span>
                  </div>
                  <div className="cti-ttp-name">{ttp.technique}</div>
                  <div className="cti-ttp-tactic-badge">{ttp.tactic}</div>
                  {ttp.evidence && (
                    <p className="cti-ttp-evidence">{ttp.evidence}</p>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Mitigations */}
        {mitreAttack && mitreAttack.some(m => m.mitigations.length > 0) && (
          <div className="cti-mitre-section">
            <h3 className="cti-section-title">
              <span className="cti-section-icon">🛡️</span>
              Mitigation Recommendations
            </h3>
            <div className="cti-mitigations-list">
              {mitreAttack?.map((item, i) => (
                item.mitigations.length > 0 && (
                  <div key={i} className="cti-mitigation-group">
                    <div className="cti-mitigation-tactic">
                      <span className="cti-tactic-badge">{item.tactic}</span>
                    </div>
                    <ul className="cti-mitigation-items">
                      {item.mitigations.map((mit, j) => (
                        <li key={j} className="cti-mitigation-item">
                          <span className="cti-mitigation-icon">✓</span>
                          <span className="cti-mitigation-text">{mit}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )
              ))}
            </div>
          </div>
        )}

        {/* Quick Actions */}
        <div className="cti-mitre-section">
          <h3 className="cti-section-title">
            <span className="cti-section-icon">⚡</span>
            Quick Actions
          </h3>
          <div className="cti-quick-actions">
            <button className="cti-action-btn">
              <span className="cti-action-icon">📋</span>
              Export Report
            </button>
            <button className="cti-action-btn">
              <span className="cti-action-icon">🔗</span>
              Share Analysis
            </button>
            <button className="cti-action-btn">
              <span className="cti-action-icon">📊</span>
              Generate IOC List
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default MITREOverlay;
