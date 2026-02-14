/**
 * MetricsGrid - Signal Distribution by Severity
 * Shows Critical/High/Medium/Low counts with visual bars
 */

import React from 'react';
import './cti-dashboard.css';

interface MetricsGridProps {
  metrics: {
    totalSignals: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    categories: Array<{ name: string; count: number; percentage: number }>;
  };
}

const MetricsGrid: React.FC<MetricsGridProps> = ({ metrics }) => {
  const SEVERITY_CONFIG = [
    { key: 'critical', label: 'Critical', color: '#E31B23' },
    { key: 'high', label: 'High', color: '#FF6B35' },
    { key: 'medium', label: 'Medium', color: '#FFB800' },
    { key: 'low', label: 'Low', color: '#00D26A' }
  ] as const;

  const getCount = (key: string): number => {
    switch (key) {
      case 'critical': return metrics.criticalCount;
      case 'high': return metrics.highCount;
      case 'medium': return metrics.mediumCount;
      case 'low': return metrics.lowCount;
      default: return 0;
    }
  };

  const getCategoryColor = (category: string): string => {
    switch (category.toLowerCase()) {
      case 'threat intel': return '#00D26A';
      case 'vulnerability': return '#FF6B35';
      case 'incident': return '#E31B23';
      default: return '#6B7280';
    }
  };

  return (
    <div className="cti-metrics-grid">
      <div className="cti-metrics-header">
        <h3 className="cti-metrics-title">Signal Distribution</h3>
        <div className="cti-metrics-total">
          <span className="cti-metrics-total-number">{metrics.totalSignals}</span>
          <span className="cti-metrics-total-label">Total Signals</span>
        </div>
      </div>

      <div className="cti-severity-bars">
        {SEVERITY_CONFIG.map((sev) => {
          const count = getCount(sev.key);
          const percentage = metrics.totalSignals > 0 
            ? Math.round((count / metrics.totalSignals) * 100) 
            : 0;

          return (
            <div key={sev.key} className="cti-severity-bar">
              <div className="cti-severity-label">
                <span 
                  className="cti-severity-dot" 
                  style={{ background: sev.color }}
                />
                <span>{sev.label}</span>
              </div>
              <div className="cti-severity-track">
                <div 
                  className="cti-severity-fill"
                  style={{ 
                    width: `${percentage}%`,
                    background: sev.color
                  }}
                />
              </div>
              <span className="cti-severity-count">{count}</span>
            </div>
          );
        })}
      </div>

      {/* Categories */}
      {metrics.categories && metrics.categories.length > 0 && (
        <div className="cti-metrics-categories">
          <h4 className="cti-categories-title">Categories</h4>
          <div className="cti-categories-chips">
            {metrics.categories.map((cat, i) => (
              <div 
                key={i} 
                className="cti-category-chip"
                style={{
                  '--chip-color': getCategoryColor(cat.name)
                } as React.CSSProperties}
              >
                <span className="cti-category-name">{cat.name}</span>
                <span className="cti-category-count">{cat.count}</span>
                <span className="cti-category-percentage">({cat.percentage}%)</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default MetricsGrid;
