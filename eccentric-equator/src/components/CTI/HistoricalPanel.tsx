/**
 * HistoricalPanel - Timeline and Historical Data
 * Collapsible bottom panel showing timeline events and sources
 */

import React, { useState } from 'react';
import './cti-dashboard.css';

interface HistoricalPanelProps {
  timeline: Array<{
    id: string;
    title: string;
    severity: string;
    category: string;
    timestamp: string;
  }>;
  sources: Array<{
    name: string;
    signalCount: number;
    lastUpdate: string;
  }>;
  baselineComparison?: {
    previousRiskScore: number;
    currentRiskScore: number;
    delta: number;
    trendDirection: string;
  };
}

const HistoricalPanel: React.FC<HistoricalPanelProps> = ({
  timeline,
  sources,
  baselineComparison
}) => {
  const [isCollapsed, setIsCollapsed] = useState(false);

  const SEVERITY_COLORS: Record<string, string> = {
    critical: '#E31B23',
    high: '#FF6B35',
    medium: '#FFB800',
    low: '#00D26A',
    info: '#6B7280'
  };

  return (
    <div className="cti-historical-panel">
      <div className="cti-historical-header" onClick={() => setIsCollapsed(!isCollapsed)}>
        <div className="cti-historical-title">
          <span>📜</span>
          <span>Historical Data & Timeline</span>
        </div>
        <button className="cti-historical-toggle">
          {isCollapsed ? '▼ Expand' : '▲ Collapse'}
        </button>
      </div>

      {!isCollapsed && (
        <div className="cti-historical-content">
          {/* Baseline Comparison */}
          {baselineComparison && (
            <div className="cti-baseline-summary">
              <h4 className="cti-section-title">Baseline Comparison</h4>
              <div className="cti-baseline-display">
                <div className="cti-baseline-item">
                  <span className="cti-baseline-label">Previous Score</span>
                  <span className="cti-baseline-value">{baselineComparison.previousRiskScore}</span>
                </div>
                <div className="cti-baseline-arrow">→</div>
                <div className="cti-baseline-item current">
                  <span className="cti-baseline-label">Current Score</span>
                  <span className="cti-baseline-value">{baselineComparison.currentRiskScore}</span>
                </div>
                <div className={`cti-baseline-delta ${baselineComparison.delta < 0 ? 'positive' : 'negative'}`}>
                  {baselineComparison.delta > 0 ? '+' : ''}{baselineComparison.delta}
                </div>
              </div>
            </div>
          )}

          {/* Timeline Events */}
          {timeline.length > 0 && (
            <div className="cti-timeline-section">
              <h4 className="cti-section-title">
                <span>⏱️</span>
                Recent Events ({timeline.length})
              </h4>
              <div className="cti-timeline-list">
                {timeline.map((event) => (
                  <div key={event.id} className="cti-timeline-item">
                    <div 
                      className="cti-timeline-severity"
                      style={{ background: SEVERITY_COLORS[event.severity] || '#6B7280' }}
                    />
                    <div className="cti-timeline-content">
                      <div className="cti-timeline-title">{event.title}</div>
                      <div className="cti-timeline-meta">
                        <span className="cti-timeline-category">{event.category}</span>
                        <span className="cti-timeline-time">
                          {new Date(event.timestamp).toLocaleDateString('en-US', {
                            month: 'short',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit'
                          })}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Intelligence Sources */}
          {sources.length > 0 && (
            <div className="cti-sources-section">
              <h4 className="cti-section-title">
                <span>📡</span>
                Active Sources
              </h4>
              <div className="cti-sources-list">
                {sources.map((source, i) => (
                  <div key={i} className="cti-source-item">
                    <div className="cti-source-indicator" />
                    <div className="cti-source-info">
                      <span className="cti-source-name">{source.name}</span>
                      <span className="cti-source-count">{source.signalCount} signals</span>
                    </div>
                    <span className="cti-source-time">
                      {new Date(source.lastUpdate).toLocaleDateString('en-US', {
                        month: 'short',
                        day: 'numeric'
                      })}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {timeline.length === 0 && sources.length === 0 && (
            <div className="cti-empty-state">
              <span className="cti-empty-icon">📭</span>
              <p className="cti-empty-text">No historical data available</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default HistoricalPanel;
