/**
 * CTI Dashboard - Security Intelligence Visualization
 * Hackfluency Cyber Threat Intelligence Public Dashboard
 */

import React, { useEffect, useState } from 'react';
import './cti-dashboard.css';

interface EvidenceLink {
  source: string;
  type: 'post' | 'host' | 'exploit' | 'feed' | 'search';
  title: string;
  url: string;
  timestamp: string;
  excerpt?: string;
}

interface CorrelationSignal {
  id: string;
  label: string;
  infraCount: number;
  socialCount: number;
  timeDeltaHours: number | null;
  interpretation: string;
  evidence: {
    infrastructure: EvidenceLink[];
    social: EvidenceLink[];
  };
}

interface CorrelationData {
  insight: string;
  pattern: 'infra-first' | 'social-first' | 'simultaneous' | 'insufficient-data';
  signals: CorrelationSignal[];
}

interface DashboardData {
  meta: {
    version: string;
    generatedAt: string;
    validUntil: string;
  };
  status: {
    riskLevel: 'critical' | 'elevated' | 'moderate' | 'low';
    riskScore: number;
    trend: 'increasing' | 'stable' | 'decreasing';
    confidenceLevel: number;
  };
  executive: {
    headline: string;
    summary: string;
    keyFindings: string[];
    recommendedActions: string[];
  };
  metrics: {
    totalSignals: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    categories: Array<{ name: string; count: number; percentage: number }>;
  };
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
  indicators: {
    cves: string[];
    domains: string[];
    ips: string[];
    keywords: string[];
  };
  correlation?: CorrelationData;
}

const RISK_COLORS = {
  critical: '#E31B23',
  elevated: '#FF6B35',
  moderate: '#FFB800',
  low: '#00D26A'
};

const SEVERITY_COLORS = {
  critical: '#E31B23',
  high: '#FF6B35',
  medium: '#FFB800',
  low: '#00D26A',
  info: '#6B7280'
};

const CTIDashboard: React.FC = () => {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadDashboard();
  }, []);

  const loadDashboard = async () => {
    try {
      const response = await fetch('/data/cti-dashboard.json');
      if (!response.ok) {
        throw new Error('Dashboard data not available');
      }
      const dashboardData = await response.json();
      setData(dashboardData);
    } catch (err) {
      setError('Intelligence data currently unavailable');
      console.error('Failed to load CTI dashboard:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="cti-loading">
        <div className="cti-loading-spinner" />
        <span>Loading Intelligence Data...</span>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="cti-container">
        <Header />
        <div className="cti-error">
          <div className="cti-error-icon">⚠</div>
          <h3>Intelligence Feed Unavailable</h3>
          <p>Threat data is being collected. Check back shortly.</p>
        </div>
        <Footer />
      </div>
    );
  }

  return (
    <div className="cti-container">
      <Header />
      
      <main className="cti-main">
        {/* Risk Status Banner */}
        <RiskBanner status={data.status} meta={data.meta} />
        
        {/* Executive Summary */}
        <ExecutiveSummary executive={data.executive} />
        
        {/* Metrics Grid */}
        <MetricsGrid metrics={data.metrics} />
        
        {/* Correlation Analysis - Cross-source intelligence */}
        {data.correlation && <CorrelationPanel correlation={data.correlation} />}
        
        {/* Two Column Layout */}
        <div className="cti-columns">
          <div className="cti-column">
            <TimelinePanel timeline={data.timeline} />
          </div>
          <div className="cti-column">
            <SourcesPanel sources={data.sources} />
            <IndicatorsPanel indicators={data.indicators} />
          </div>
        </div>
      </main>
      
      <Footer generatedAt={data.meta.generatedAt} />
    </div>
  );
};

const Header: React.FC = () => (
  <header className="cti-header">
    <div className="cti-header-content">
      <div className="cti-logo">
        <span className="cti-logo-icon">◆</span>
        <span className="cti-logo-text">HACKFLUENCY</span>
      </div>
      <h1 className="cti-title">Security Intelligence Dashboard</h1>
      <p className="cti-subtitle">Automated Threat Intelligence Collection & Analysis</p>
    </div>
  </header>
);

const RiskBanner: React.FC<{ status: DashboardData['status']; meta: DashboardData['meta'] }> = ({ status, meta }) => {
  const riskColor = RISK_COLORS[status.riskLevel];
  const trendIcon = status.trend === 'increasing' ? '↑' : status.trend === 'decreasing' ? '↓' : '→';
  
  return (
    <section className="cti-risk-banner" style={{ borderColor: riskColor }}>
      <div className="cti-risk-indicator">
        <div 
          className="cti-risk-circle" 
          style={{ 
            background: `conic-gradient(${riskColor} ${status.riskScore * 3.6}deg, #2a2a2a ${status.riskScore * 3.6}deg)` 
          }}
        >
          <div className="cti-risk-inner">
            <span className="cti-risk-score">{status.riskScore}</span>
          </div>
        </div>
        <div className="cti-risk-label" style={{ color: riskColor }}>
          {status.riskLevel.toUpperCase()} RISK
        </div>
      </div>
      
      <div className="cti-risk-details">
        <div className="cti-risk-row">
          <span className="cti-risk-label-small">Trend</span>
          <span className={`cti-risk-trend cti-trend-${status.trend}`}>
            {trendIcon} {status.trend}
          </span>
        </div>
        <div className="cti-risk-row">
          <span className="cti-risk-label-small">Confidence</span>
          <span className="cti-risk-confidence">{status.confidenceLevel}%</span>
        </div>
        <div className="cti-risk-row">
          <span className="cti-risk-label-small">Valid Until</span>
          <span className="cti-risk-validity">
            {new Date(meta.validUntil).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}
          </span>
        </div>
      </div>
    </section>
  );
};

const ExecutiveSummary: React.FC<{ executive: DashboardData['executive'] }> = ({ executive }) => (
  <section className="cti-section cti-executive">
    <h2 className="cti-section-title">{executive.headline}</h2>
    <p className="cti-executive-summary">{executive.summary}</p>
    
    <div className="cti-executive-grid">
      <div className="cti-executive-card">
        <h3>Key Findings</h3>
        <ul>
          {executive.keyFindings.map((finding, i) => (
            <li key={i}>{finding}</li>
          ))}
        </ul>
      </div>
      <div className="cti-executive-card cti-executive-actions">
        <h3>Recommended Actions</h3>
        <ul>
          {executive.recommendedActions.map((action, i) => (
            <li key={i}>{action}</li>
          ))}
        </ul>
      </div>
    </div>
  </section>
);

const MetricsGrid: React.FC<{ metrics: DashboardData['metrics'] }> = ({ metrics }) => (
  <section className="cti-section cti-metrics">
    <div className="cti-metrics-header">
      <h2 className="cti-section-title">Signal Distribution</h2>
      <div className="cti-metrics-total">
        <span className="cti-metrics-total-number">{metrics.totalSignals}</span>
        <span className="cti-metrics-total-label">Total Signals</span>
      </div>
    </div>
    
    <div className="cti-severity-bars">
      <SeverityBar label="Critical" count={metrics.criticalCount} total={metrics.totalSignals} color={SEVERITY_COLORS.critical} />
      <SeverityBar label="High" count={metrics.highCount} total={metrics.totalSignals} color={SEVERITY_COLORS.high} />
      <SeverityBar label="Medium" count={metrics.mediumCount} total={metrics.totalSignals} color={SEVERITY_COLORS.medium} />
      <SeverityBar label="Low" count={metrics.lowCount} total={metrics.totalSignals} color={SEVERITY_COLORS.low} />
    </div>
    
    {metrics.categories.length > 0 && (
      <div className="cti-categories">
        <h3>Categories</h3>
        <div className="cti-category-chips">
          {metrics.categories.map((cat, i) => (
            <div key={i} className="cti-category-chip">
              <span className="cti-category-name">{cat.name}</span>
              <span className="cti-category-count">{cat.count}</span>
            </div>
          ))}
        </div>
      </div>
    )}
  </section>
);

const SeverityBar: React.FC<{ label: string; count: number; total: number; color: string }> = ({ label, count, total, color }) => {
  const percentage = total > 0 ? Math.round((count / total) * 100) : 0;
  
  return (
    <div className="cti-severity-bar">
      <div className="cti-severity-label">
        <span className="cti-severity-dot" style={{ background: color }} />
        <span>{label}</span>
      </div>
      <div className="cti-severity-track">
        <div 
          className="cti-severity-fill" 
          style={{ width: `${percentage}%`, background: color }} 
        />
      </div>
      <div className="cti-severity-count">{count}</div>
    </div>
  );
};

const TimelinePanel: React.FC<{ timeline: DashboardData['timeline'] }> = ({ timeline }) => (
  <section className="cti-section cti-timeline">
    <h2 className="cti-section-title">Recent Activity</h2>
    {timeline.length === 0 ? (
      <p className="cti-empty">No recent activity recorded</p>
    ) : (
      <div className="cti-timeline-list">
        {timeline.map((item, i) => (
          <div key={item.id} className="cti-timeline-item">
            <div 
              className="cti-timeline-severity" 
              style={{ background: SEVERITY_COLORS[item.severity as keyof typeof SEVERITY_COLORS] || '#6B7280' }} 
            />
            <div className="cti-timeline-content">
              <div className="cti-timeline-title">{item.title}</div>
              <div className="cti-timeline-meta">
                <span className="cti-timeline-category">{item.category}</span>
                <span className="cti-timeline-time">
                  {new Date(item.timestamp).toLocaleDateString('en-US', { 
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
    )}
  </section>
);

const SourcesPanel: React.FC<{ sources: DashboardData['sources'] }> = ({ sources }) => (
  <section className="cti-section cti-sources">
    <h2 className="cti-section-title">Intelligence Sources</h2>
    {sources.length === 0 ? (
      <p className="cti-empty">No active sources</p>
    ) : (
      <div className="cti-sources-list">
        {sources.map((source, i) => (
          <div key={i} className="cti-source-item">
            <div className="cti-source-indicator" />
            <div className="cti-source-info">
              <span className="cti-source-name">{source.name}</span>
              <span className="cti-source-count">{source.signalCount} signals</span>
            </div>
          </div>
        ))}
      </div>
    )}
    <p className="cti-sources-note">
      Sources are aggregated and analyzed automatically. Additional context enrichment is applied during processing.
    </p>
  </section>
);

const IndicatorsPanel: React.FC<{ indicators: DashboardData['indicators'] }> = ({ indicators }) => {
  const hasCves = indicators.cves.length > 0;
  const hasKeywords = indicators.keywords.length > 0;
  
  if (!hasCves && !hasKeywords) return null;
  
  return (
    <section className="cti-section cti-indicators">
      <h2 className="cti-section-title">Key Indicators</h2>
      
      {hasCves && (
        <div className="cti-indicator-group">
          <h4>CVE References</h4>
          <div className="cti-indicator-tags">
            {indicators.cves.map((cve, i) => (
              <span key={i} className="cti-indicator-tag cti-tag-cve">{cve}</span>
            ))}
          </div>
        </div>
      )}
      
      {hasKeywords && (
        <div className="cti-indicator-group">
          <h4>Trending Keywords</h4>
          <div className="cti-indicator-tags">
            {indicators.keywords.map((keyword, i) => (
              <span key={i} className="cti-indicator-tag cti-tag-keyword">{keyword}</span>
            ))}
          </div>
        </div>
      )}
    </section>
  );
};

/**
 * Correlation Panel - Shows cross-source intelligence correlation with evidence links
 */
const CorrelationPanel: React.FC<{ correlation: CorrelationData }> = ({ correlation }) => {
  const patternLabels: Record<string, string> = {
    'infra-first': 'Infrastructure First',
    'social-first': 'Social First',
    'simultaneous': 'Simultaneous',
    'insufficient-data': 'Insufficient Data'
  };

  return (
    <section className="cti-section cti-correlation">
      <div className="cti-correlation-header">
        <h2 className="cti-section-title">Cross-Source Correlation</h2>
        <div className="cti-correlation-pattern">
          <span className="cti-pattern-label">Pattern:</span>
          <span className={`cti-pattern-badge cti-pattern-${correlation.pattern}`}>
            {patternLabels[correlation.pattern]}
          </span>
        </div>
      </div>
      
      <p className="cti-correlation-insight">{correlation.insight}</p>
      
      <div className="cti-correlation-signals">
        {correlation.signals.map((signal) => (
          <div key={signal.id} className="cti-correlation-signal">
            <div className="cti-signal-header">
              <h3 className="cti-signal-label">{signal.label}</h3>
              <div className="cti-signal-counts">
                <span className="cti-count-infra" title="Infrastructure signals">
                  🖥 {signal.infraCount}
                </span>
                <span className="cti-count-social" title="Social signals">
                  💬 {signal.socialCount}
                </span>
                {signal.timeDeltaHours !== null && (
                  <span className="cti-time-delta" title="Time difference">
                    ⏱ {signal.timeDeltaHours.toFixed(1)}h
                  </span>
                )}
              </div>
            </div>
            
            <p className="cti-signal-interpretation">{signal.interpretation}</p>
            
            {/* Evidence Links */}
            <div className="cti-evidence-container">
              {signal.evidence.infrastructure.length > 0 && (
                <div className="cti-evidence-group">
                  <h4 className="cti-evidence-title">Infrastructure Evidence</h4>
                  <div className="cti-evidence-links">
                    {signal.evidence.infrastructure.map((ev, i) => (
                      <a 
                        key={i} 
                        href={ev.url} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="cti-evidence-link cti-evidence-infra"
                        title={ev.excerpt || ev.title}
                      >
                        <span className="cti-evidence-icon">🔍</span>
                        <span className="cti-evidence-text">{ev.title}</span>
                        <span className="cti-evidence-arrow">↗</span>
                      </a>
                    ))}
                  </div>
                </div>
              )}
              
              {signal.evidence.social.length > 0 && (
                <div className="cti-evidence-group">
                  <h4 className="cti-evidence-title">Social Intelligence</h4>
                  <div className="cti-evidence-links">
                    {signal.evidence.social.map((ev, i) => (
                      <a 
                        key={i} 
                        href={ev.url} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="cti-evidence-link cti-evidence-social"
                        title={ev.excerpt || ev.title}
                      >
                        <span className="cti-evidence-icon">💬</span>
                        <span className="cti-evidence-text">{ev.excerpt ? ev.excerpt.substring(0, 50) + '...' : ev.title}</span>
                        <span className="cti-evidence-arrow">↗</span>
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
      
      <p className="cti-correlation-note">
        Evidence links open external sources for verification. Infrastructure data from Shodan, social intelligence from X.com.
      </p>
    </section>
  );
};

const Footer: React.FC<{ generatedAt?: string }> = ({ generatedAt }) => (
  <footer className="cti-footer">
    <div className="cti-footer-content">
      <p className="cti-footer-disclaimer">
        This intelligence dashboard presents aggregated threat signals from public sources. 
        Data is collected and analyzed automatically. Findings should be validated before operational decisions.
      </p>
      <div className="cti-footer-meta">
        {generatedAt && (
          <span className="cti-footer-timestamp">
            Last updated: {new Date(generatedAt).toLocaleString('en-US', { 
              dateStyle: 'medium', 
              timeStyle: 'short' 
            })}
          </span>
        )}
        <span className="cti-footer-brand">Powered by Hackfluency Intelligence</span>
      </div>
    </div>
  </footer>
);

export default CTIDashboard;
