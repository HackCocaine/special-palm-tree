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

// ==================== New Assessment Layer Types ====================

interface QuantifiedCorrelation {
  score: number;
  strength: 'weak' | 'moderate' | 'strong';
  factors: {
    cveOverlap: number;
    serviceMatch: number;
    temporalProximity: number;
    infraSocialAlignment: number;
  };
  explanation: string;
}

interface BaselineComparison {
  previousRiskScore: number;
  currentRiskScore: number;
  delta: number;
  anomalyLevel: 'stable' | 'mild' | 'moderate' | 'severe';
  trendDirection: 'increasing' | 'stable' | 'decreasing';
}

interface DataFreshness {
  socialAgeHours: number;
  infraAgeHours: number;
  freshnessScore: number;
  status: 'high' | 'moderate' | 'stale';
}

interface IndicatorStatistics {
  uniqueCVECount: number;
  uniqueDomainCount: number;
  uniqueIPCount: number;
  uniquePortCount: number;
  uniqueServiceCount: number;
  totalIndicators: number;
  duplicates: number;
  duplicationRatio: number;
}

interface RiskComputation {
  weights: {
    vulnerabilityRatio: number;
    socialIntensity: number;
    correlationScore: number;
    freshnessScore: number;
    baselineDelta: number;
  };
  components: {
    vulnerabilityRatio: number;
    socialIntensity: number;
    correlationScore: number;
    freshnessScore: number;
    baselineDelta: number;
  };
  computedScore: number;
  confidenceLevel: number;
}

interface ThreatClassification {
  type: 'opportunistic' | 'targeted' | 'campaign';
  confidence: number;
  rationale: string;
  indicators: string[];
}

interface ModelMetadata {
  strategic: string;
  technical: string;
  quantization?: string;
  version?: string;
}

interface AssessmentLayer {
  correlation: QuantifiedCorrelation;
  scoring: RiskComputation;
  baselineComparison: BaselineComparison;
  freshness: DataFreshness;
  classification: ThreatClassification;
  iocStats: IndicatorStatistics;
  narrative: string;
}

// ==================== Dashboard Data Types ====================

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
  // Infrastructure exposure data
  infrastructure?: {
    totalHosts: number;
    exposedPorts: Array<{
      port: number;
      service: string;
      count: number;
      percentage: number;
    }>;
    topCountries: Array<{
      country: string;
      count: number;
    }>;
    vulnerableHosts: number;
    sampleHosts: Array<{
      ip: string;
      port: number;
      service: string;
      vulns: string[];
    }>;
  };
  // Social intelligence data (aligned with new orchestrator output)
  socialIntel?: {
    totalPosts: number;
    themes: string[];
    tone: 'speculative' | 'confirmed' | 'mixed';
    topPosts: Array<{
      excerpt: string;
      author: string;
      engagement: number;
      url?: string;
    }>;
  };
  // Multi-agent CTI analysis
  ctiAnalysis?: {
    model: string;
    killChainPhase: string;
    threatLandscape: string;
    analystBrief?: string;
    analystExecutive?: {
      situation: string;
      evidence: string;
      impact: string;
      actions: string[];
    };
    methodologies?: string[];
    observableSummary?: string[];
    mitreAttack: Array<{
      tactic: string;
      techniques: string[];
      mitigations: string[];
    }>;
    keyFindings: Array<{
      finding: string;
      severity: string;
      evidence: string;
      recommendation: string;
    }>;
    ttps: Array<{
      technique: string;
      techniqueId: string;
      tactic: string;
      evidence: string;
      confidence: number;
    }>;
    temporalPatterns: Array<{
      pattern: string;
      description: string;
      timeframe: string;
      confidence: number;
      evidence: Array<{ source: string; excerpt: string; url: string }>;
    }>;
    crossSourceLinks: Array<{
      infraSignal: string;
      socialSignal: string;
      relationship: string;
      timeDelta: string;
      significance: string;
    }>;
    immediateActions: string[];
    strategicRecommendations: string[];
    sourcesAndReferences: Array<{
      source: string;
      url: string;
      relevance: string;
    }>;
  };
  // New assessment layer from minimal architecture
  assessmentLayer?: AssessmentLayer;
  modelMetadata?: ModelMetadata;
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
  const [isRefreshing, setIsRefreshing] = useState(false);

  useEffect(() => {
    loadDashboard();
  }, []);

  const loadDashboard = async (isManualRefresh = false) => {
    if (isManualRefresh) {
      setIsRefreshing(true);
    }
    try {
      const cacheBuster = `?_cb=${Date.now()}`;
      const response = await fetch(`/data/cti-dashboard.json${cacheBuster}`);
      if (!response.ok) {
        throw new Error('Dashboard data not available');
      }
      const dashboardData = await response.json();
      setData(dashboardData);
      setError(null);
    } catch (err) {
      setError('Intelligence data currently unavailable');
      console.error('Failed to load CTI dashboard:', err);
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  };

  const handleRefresh = () => {
    loadDashboard(true);
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
        {/* Risk Banner - Overall threat status */}
        <RiskBanner status={data.status} meta={data.meta} />
        
        {/* Executive Summary */}
        <ExecutiveSummary executive={data.executive} />

        {/* Assessment Layer Panel - Quantified analysis */}
        {data.assessmentLayer && (
          <AssessmentLayerPanel 
            assessment={data.assessmentLayer} 
            modelMetadata={data.modelMetadata}
          />
        )}
        
        {/* CTI Analysis - Correlation insights */}
        {data.ctiAnalysis && (
          <CTIAnalysisPanel analysis={data.ctiAnalysis} />
        )}
        
        {/* Two-column layout for Infrastructure and Social Intel */}
        <div className="cti-intel-grid">
          {/* Infrastructure Exposure */}
          {data.infrastructure && data.infrastructure.totalHosts > 0 && (
            <InfrastructurePanel infrastructure={data.infrastructure} />
          )}
          
          {/* Social Intelligence */}
          {data.socialIntel && data.socialIntel.topPosts.length > 0 && (
            <SocialIntelPanel socialIntel={data.socialIntel} />
          )}
        </div>
        
        {/* Indicators of Compromise */}
        {data.indicators && (
          <IndicatorsPanel indicators={data.indicators} />
        )}
      </main>
      
      <Footer 
        generatedAt={data.meta.generatedAt} 
        onRefresh={handleRefresh}
        isRefreshing={isRefreshing}
      />
    </div>
  );
};

const cleanDisplayText = (text: string): string => {
  if (!text) return '';
  return text
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/\*([^*\n]+)\*/g, '$1')
    .replace(/^#{1,6}\s*/gm, '')
    .replace(/\*\*:\s*/g, ': ')
    .replace(/\s{2,}/g, ' ')
    .trim();
};

const Header: React.FC = () => (
  <header className="cti-header">
    <div className="cti-header-content">
      <div className="cti-logo">
        <span className="cti-logo-icon">◆</span>
        <span className="cti-logo-text">HACKFLUENCY</span>
      </div>
      <h1 className="cti-title">Threat Intelligence Correlation</h1>
      <p className="cti-subtitle">Context-aware analysis: Social signals → Infrastructure exposure</p>
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

/**
 * Infrastructure Panel - Shows exposed infrastructure from Shodan
 */
const InfrastructurePanel: React.FC<{ infrastructure: NonNullable<DashboardData['infrastructure']> }> = ({ infrastructure }) => {
  return (
    <section className="cti-section cti-infrastructure">
      <div className="cti-infra-header">
        <h2 className="cti-section-title">🖥️ Infrastructure Exposure</h2>
        <div className="cti-infra-stats">
          <span className="cti-stat-badge cti-stat-hosts">{infrastructure.totalHosts} hosts</span>
          {infrastructure.vulnerableHosts > 0 && (
            <span className="cti-stat-badge cti-stat-vuln">{infrastructure.vulnerableHosts} vulnerable</span>
          )}
        </div>
      </div>
      
      <div className="cti-infra-content">
        {/* Exposed Ports */}
        <div className="cti-infra-ports">
          <h4>Exposed Services</h4>
          <div className="cti-port-list">
            {infrastructure.exposedPorts.map((item, i) => (
              <div key={i} className="cti-port-item">
                <span className="cti-port-number">{item.port}</span>
                <span className="cti-port-service">{item.service}</span>
                <div className="cti-port-bar">
                  <div className="cti-port-fill" style={{ width: `${item.percentage}%` }} />
                </div>
                <span className="cti-port-count">{item.count}</span>
              </div>
            ))}
          </div>
        </div>
        
        {/* Top Countries */}
        {infrastructure.topCountries.length > 0 && (
          <div className="cti-infra-countries">
            <h4>Geographic Distribution</h4>
            <div className="cti-country-chips">
              {infrastructure.topCountries.map((item, i) => (
                <span key={i} className="cti-country-chip">
                  {item.country} <span className="cti-country-count">({item.count})</span>
                </span>
              ))}
            </div>
          </div>
        )}
        
        {/* Vulnerable Hosts Detected */}
        {infrastructure.sampleHosts.length > 0 && (
          <div className="cti-infra-samples">
            <h4>Vulnerable Hosts Detected</h4>
            <div className="cti-sample-list">
              {infrastructure.sampleHosts.map((host, i) => (
                <div key={i} className="cti-sample-host">
                  <div className="cti-host-info">
                    <span className="cti-host-ip">{host.ip}:{host.port}</span>
                    <span className="cti-host-service">{host.service}</span>
                  </div>
                  <div className="cti-host-vulns">
                    {host.vulns.map((vuln, j) => (
                      <a 
                        key={j}
                        href={`https://nvd.nist.gov/vuln/detail/${vuln}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="cti-vuln-tag"
                      >
                        {vuln}
                      </a>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
      
      <p className="cti-infra-note">
        Data collected via <a href="https://www.shodan.io" target="_blank" rel="noopener noreferrer">Shodan</a>. 
        IP addresses are partially masked for privacy.
      </p>
    </section>
  );
};

/**
 * Social Intelligence Panel - Shows social media threat discussions
 */
const SocialIntelPanel: React.FC<{ socialIntel: NonNullable<DashboardData['socialIntel']> }> = ({ socialIntel }) => {
  const toneColors: Record<string, string> = {
    confirmed: '#E31B23',
    mixed: '#FFB800',
    speculative: '#00D26A'
  };

  return (
    <section className="cti-section cti-social">
      <div className="cti-social-header">
        <h2 className="cti-section-title">💬 Social Intelligence</h2>
        <div className="cti-social-stats">
          <span className="cti-stat-badge cti-stat-posts">{socialIntel.totalPosts} posts</span>
          <span 
            className="cti-stat-badge cti-stat-sentiment" 
            style={{ borderColor: toneColors[socialIntel.tone] || '#FFB800' }}
          >
            {socialIntel.tone}
          </span>
        </div>
      </div>
      
      <div className="cti-social-content">
        {/* Themes */}
        {socialIntel.themes.length > 0 && (
          <div className="cti-social-topics">
            <h4>Detected Themes</h4>
            <div className="cti-theme-chips">
              {socialIntel.themes.map((theme, i) => (
                <span key={i} className="cti-theme-chip">
                  {theme}
                </span>
              ))}
            </div>
          </div>
        )}
        
        {/* Top Posts */}
        <div className="cti-social-posts">
          <h4>Top Discussions</h4>
          <div className="cti-post-list">
            {socialIntel.topPosts.map((post, i) => (
              <a 
                key={i} 
                href={post.url || '#'}
                target="_blank"
                rel="noopener noreferrer"
                className="cti-post-item"
              >
                <div className="cti-post-meta">
                  <span className="cti-post-author">@{post.author}</span>
                </div>
                <p className="cti-post-excerpt">{post.excerpt}</p>
                <div className="cti-post-engagement">
                  <span>❤️ {post.engagement}</span>
                  {post.url && <span className="cti-post-link-icon">↗</span>}
                </div>
              </a>
            ))}
          </div>
        </div>
      </div>
      
      <p className="cti-social-note">
        Intelligence gathered from <a href="https://x.com" target="_blank" rel="noopener noreferrer">X.com</a>. 
        Posts sorted by engagement and relevance.
      </p>
    </section>
  );
};

/**
 * Indicators Panel - Shows CVEs, IPs, domains, keywords
 */
const IndicatorsPanel: React.FC<{ indicators: DashboardData['indicators'] }> = ({ indicators }) => {
  if (!indicators) return null;
  
  const hasIndicators = indicators.cves.length > 0 || indicators.ips.length > 0 || 
                        indicators.domains.length > 0 || indicators.keywords.length > 0;
  
  if (!hasIndicators) return null;

  return (
    <section className="cti-section cti-indicators">
      <h2 className="cti-section-title">🎯 Indicators of Compromise</h2>
      
      <div className="cti-indicators-grid">
        {indicators.cves.length > 0 && (
          <div className="cti-indicator-group">
            <h4>CVEs ({indicators.cves.length})</h4>
            <div className="cti-indicator-list">
              {indicators.cves.map((cve, i) => (
                <a 
                  key={i}
                  href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="cti-indicator-tag cti-indicator-cve"
                >
                  {cve}
                </a>
              ))}
            </div>
          </div>
        )}
        
        {indicators.ips.length > 0 && (
          <div className="cti-indicator-group">
            <h4>IP Addresses ({indicators.ips.length})</h4>
            <div className="cti-indicator-list">
              {indicators.ips.map((ip, i) => (
                <span key={i} className="cti-indicator-tag cti-indicator-ip">{ip}</span>
              ))}
            </div>
          </div>
        )}
        
        {indicators.domains.length > 0 && (
          <div className="cti-indicator-group">
            <h4>Domains ({indicators.domains.length})</h4>
            <div className="cti-indicator-list">
              {indicators.domains.map((domain, i) => (
                <span key={i} className="cti-indicator-tag cti-indicator-domain">{domain}</span>
              ))}
            </div>
          </div>
        )}
        
        {indicators.keywords.length > 0 && (
          <div className="cti-indicator-group">
            <h4>Keywords ({indicators.keywords.length})</h4>
            <div className="cti-indicator-list">
              {indicators.keywords.map((kw, i) => (
                <span key={i} className="cti-indicator-tag cti-indicator-keyword">{kw}</span>
              ))}
            </div>
          </div>
        )}
      </div>
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

/**
 * Assessment Layer Panel - Displays quantified correlation, baseline comparison,
 * data freshness, indicator statistics, risk computation, and threat classification
 */
const AssessmentLayerPanel: React.FC<{
  assessment: AssessmentLayer;
  modelMetadata?: ModelMetadata;
}> = ({ assessment, modelMetadata }) => {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['correlation', 'risk']));

  const toggleSection = (section: string) => {
    const newSet = new Set(expandedSections);
    if (newSet.has(section)) {
      newSet.delete(section);
    } else {
      newSet.add(section);
    }
    setExpandedSections(newSet);
  };

  const correlationColor = assessment.correlation.strength === 'strong' ? '#00D26A' :
                          assessment.correlation.strength === 'moderate' ? '#FFB800' : '#E31B23';

  const anomalyColor = assessment.baselineComparison.anomalyLevel === 'stable' ? '#00D26A' :
                       assessment.baselineComparison.anomalyLevel === 'mild' ? '#FFB800' :
                       assessment.baselineComparison.anomalyLevel === 'moderate' ? '#FF6B35' : '#E31B23';

  const freshnessColor = assessment.freshness.status === 'high' ? '#00D26A' :
                         assessment.freshness.status === 'moderate' ? '#FFB800' : '#E31B23';

  const threatTypeColors: Record<string, string> = {
    opportunistic: '#00D26A',
    targeted: '#E31B23',
    campaign: '#FF6B35'
  };

  return (
    <section className="cti-section cti-assessment">
      <div className="cti-assessment-header">
        <h2 className="cti-section-title">Quantified Assessment</h2>
        {modelMetadata && (
          <div className="cti-model-meta">
            <span className="cti-model-tag" title="Strategic Model">{modelMetadata.strategic.split('/').pop()}</span>
            <span className="cti-model-tag" title="Technical Model">{modelMetadata.technical.split('/').pop()}</span>
          </div>
        )}
      </div>

      {/* Narrative Summary */}
      <div className="cti-assessment-narrative">
        <p>{assessment.narrative}</p>
      </div>

      {/* Threat Classification */}
      <div className="cti-classification-card">
        <div className="cti-classification-header">
          <span 
            className="cti-classification-badge"
            style={{ backgroundColor: threatTypeColors[assessment.classification.type] }}
          >
            {assessment.classification.type.toUpperCase()}
          </span>
          <span className="cti-classification-confidence">
            {assessment.classification.confidence}% confidence
          </span>
        </div>
        <p className="cti-classification-rationale">{assessment.classification.rationale}</p>
        {assessment.classification.indicators.length > 0 && (
          <div className="cti-classification-indicators">
            {assessment.classification.indicators.map((ind, i) => (
              <span key={i} className="cti-indicator-chip">{ind}</span>
            ))}
          </div>
        )}
      </div>

      {/* Quantified Correlation */}
      <div className="cti-analysis-section">
        <button 
          className="cti-section-toggle"
          onClick={() => toggleSection('correlation')}
        >
          <span>
            Correlation Analysis: 
            <span style={{ color: correlationColor, fontWeight: 'bold' }}>
              {assessment.correlation.strength} ({Math.round(assessment.correlation.score * 100)}%)
            </span>
          </span>
          <span className="cti-toggle-icon">{expandedSections.has('correlation') ? '▼' : '▶'}</span>
        </button>
        
        {expandedSections.has('correlation') && (
          <div className="cti-correlation-details">
            <p className="cti-correlation-explanation">{assessment.correlation.explanation}</p>
            <div className="cti-factor-grid">
              <div className="cti-factor-item">
                <span className="cti-factor-label">CVE Overlap</span>
                <div className="cti-factor-bar">
                  <div 
                    className="cti-factor-fill" 
                    style={{ width: `${assessment.correlation.factors.cveOverlap * 100}%` }}
                  />
                </div>
                <span className="cti-factor-value">{Math.round(assessment.correlation.factors.cveOverlap * 100)}%</span>
              </div>
              <div className="cti-factor-item">
                <span className="cti-factor-label">Service Match</span>
                <div className="cti-factor-bar">
                  <div 
                    className="cti-factor-fill" 
                    style={{ width: `${assessment.correlation.factors.serviceMatch * 100}%` }}
                  />
                </div>
                <span className="cti-factor-value">{Math.round(assessment.correlation.factors.serviceMatch * 100)}%</span>
              </div>
              <div className="cti-factor-item">
                <span className="cti-factor-label">Temporal Proximity</span>
                <div className="cti-factor-bar">
                  <div 
                    className="cti-factor-fill" 
                    style={{ width: `${assessment.correlation.factors.temporalProximity * 100}%` }}
                  />
                </div>
                <span className="cti-factor-value">{Math.round(assessment.correlation.factors.temporalProximity * 100)}%</span>
              </div>
              <div className="cti-factor-item">
                <span className="cti-factor-label">Infra-Social Alignment</span>
                <div className="cti-factor-bar">
                  <div 
                    className="cti-factor-fill" 
                    style={{ width: `${assessment.correlation.factors.infraSocialAlignment * 100}%` }}
                  />
                </div>
                <span className="cti-factor-value">{Math.round(assessment.correlation.factors.infraSocialAlignment * 100)}%</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Baseline Comparison */}
      <div className="cti-analysis-section">
        <button 
          className="cti-section-toggle"
          onClick={() => toggleSection('baseline')}
        >
          <span>
            Baseline Comparison: 
            <span style={{ color: anomalyColor, fontWeight: 'bold' }}>
              {assessment.baselineComparison.anomalyLevel}
            </span>
            {assessment.baselineComparison.delta !== 0 && (
              <span className={assessment.baselineComparison.delta > 0 ? 'cti-delta-positive' : 'cti-delta-negative'}>
                {' '}({assessment.baselineComparison.delta > 0 ? '+' : ''}{assessment.baselineComparison.delta})
              </span>
            )}
          </span>
          <span className="cti-toggle-icon">{expandedSections.has('baseline') ? '▼' : '▶'}</span>
        </button>
        
        {expandedSections.has('baseline') && (
          <div className="cti-baseline-details">
            <div className="cti-baseline-scores">
              <div className="cti-baseline-item">
                <span className="cti-baseline-label">Previous</span>
                <span className="cti-baseline-value">{assessment.baselineComparison.previousRiskScore}</span>
              </div>
              <div className="cti-baseline-arrow">→</div>
              <div className="cti-baseline-item">
                <span className="cti-baseline-label">Current</span>
                <span className="cti-baseline-value">{assessment.baselineComparison.currentRiskScore}</span>
              </div>
            </div>
            <p className="cti-trend-label">
              Trend: <span className={`cti-trend-${assessment.baselineComparison.trendDirection}`}>
                {assessment.baselineComparison.trendDirection}
              </span>
            </p>
          </div>
        )}
      </div>

      {/* Risk Computation */}
      <div className="cti-analysis-section">
        <button 
          className="cti-section-toggle"
          onClick={() => toggleSection('risk')}
        >
          <span>
            Risk Score: 
            <span className="cti-risk-value">{assessment.scoring.computedScore}</span>
            {' '}(confidence: {assessment.scoring.confidenceLevel}%)
          </span>
          <span className="cti-toggle-icon">{expandedSections.has('risk') ? '▼' : '▶'}</span>
        </button>
        
        {expandedSections.has('risk') && (
          <div className="cti-risk-details">
            <div className="cti-risk-components">
              <h4>Risk Components</h4>
              {Object.entries(assessment.scoring.components).map(([key, value]) => (
                <div key={key} className="cti-risk-component">
                  <span className="cti-component-label">
                    {key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                  </span>
                  <div className="cti-component-bar">
                    <div 
                      className="cti-component-fill" 
                      style={{ width: `${value * 100}%` }}
                    />
                  </div>
                  <span className="cti-component-weight">
                    weight: {Math.round(assessment.scoring.weights[key as keyof typeof assessment.scoring.weights] * 100)}%
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Data Freshness */}
      <div className="cti-freshness-bar">
        <div className="cti-freshness-item">
          <span className="cti-freshness-label">Data Freshness</span>
          <span 
            className="cti-freshness-badge"
            style={{ backgroundColor: freshnessColor }}
          >
            {assessment.freshness.status.toUpperCase()}
          </span>
        </div>
        <div className="cti-freshness-score">
          Score: {Math.round(assessment.freshness.freshnessScore * 100)}%
        </div>
        <div className="cti-freshness-ages">
          <span>Social: {assessment.freshness.socialAgeHours}h old</span>
          <span>Infrastructure: {assessment.freshness.infraAgeHours}h old</span>
        </div>
      </div>

      {/* Indicator Statistics */}
      <div className="cti-ioc-stats">
        <h4>Indicator Statistics</h4>
        <div className="cti-ioc-grid">
          <div className="cti-ioc-item">
            <span className="cti-ioc-value">{assessment.iocStats.uniqueCVECount}</span>
            <span className="cti-ioc-label">CVEs</span>
          </div>
          <div className="cti-ioc-item">
            <span className="cti-ioc-value">{assessment.iocStats.uniqueDomainCount}</span>
            <span className="cti-ioc-label">Domains</span>
          </div>
          <div className="cti-ioc-item">
            <span className="cti-ioc-value">{assessment.iocStats.uniqueIPCount}</span>
            <span className="cti-ioc-label">IPs</span>
          </div>
          <div className="cti-ioc-item">
            <span className="cti-ioc-value">{assessment.iocStats.totalIndicators}</span>
            <span className="cti-ioc-label">Total</span>
          </div>
          {assessment.iocStats.duplicationRatio > 0 && (
            <div className="cti-ioc-item cti-ioc-duplicates">
              <span className="cti-ioc-value">{Math.round(assessment.iocStats.duplicationRatio * 100)}%</span>
              <span className="cti-ioc-label">Duplicates</span>
            </div>
          )}
        </div>
      </div>
    </section>
  );
};

/**
 * CTI Analysis Panel - Multi-agent analysis with TTPs, MITRE mapping, and evidence
 */
const CTIAnalysisPanel: React.FC<{ analysis: NonNullable<DashboardData['ctiAnalysis']> }> = ({ analysis }) => {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['patterns', 'cross', 'ttps']));

  const toggleSection = (section: string) => {
    const newSet = new Set(expandedSections);
    if (newSet.has(section)) {
      newSet.delete(section);
    } else {
      newSet.add(section);
    }
    setExpandedSections(newSet);
  };

  return (
    <section className="cti-section cti-analysis">
      <div className="cti-analysis-header">
        <h2 className="cti-section-title">CTI Correlation Analysis</h2>
        <div className="cti-analysis-meta">
          <span className="cti-analysis-model" title="Analysis model">
            {analysis.model}
          </span>
          {analysis.killChainPhase && (
            <span className="cti-analysis-phase" title="Kill Chain Phase">
              {analysis.killChainPhase}
            </span>
          )}
        </div>
      </div>

      {/* Threat Landscape Summary */}
      {analysis.threatLandscape && (
        <div className="cti-threat-landscape">
          <p>{cleanDisplayText(analysis.threatLandscape)}</p>
        </div>
      )}

      {analysis.analystExecutive ? (
        <div className="cti-threat-landscape">
          <h3 className="cti-section-title" style={{ fontSize: '1rem', marginBottom: '0.5rem' }}>CTI Analyst JR Summary</h3>
          <ul>
            <li><strong>Situation:</strong> {cleanDisplayText(analysis.analystExecutive.situation)}</li>
            <li><strong>Evidence:</strong> {cleanDisplayText(analysis.analystExecutive.evidence)}</li>
            <li><strong>Impact:</strong> {cleanDisplayText(analysis.analystExecutive.impact)}</li>
            {analysis.analystExecutive.actions.map((action, idx) => (
              <li key={idx}><strong>{`P${idx + 1}`}</strong> {cleanDisplayText(action)}</li>
            ))}
          </ul>
        </div>
      ) : analysis.analystBrief && (
        <div className="cti-threat-landscape">
          <h3 className="cti-section-title" style={{ fontSize: '1rem', marginBottom: '0.5rem' }}>CTI Analyst JR Summary</h3>
          <p>{cleanDisplayText(analysis.analystBrief)}</p>
        </div>
      )}

      {analysis.observableSummary && analysis.observableSummary.length > 0 && (
        <div className="cti-threat-landscape">
          <h3 className="cti-section-title" style={{ fontSize: '1rem', marginBottom: '0.5rem' }}>Current Observables</h3>
          <ul>
            {analysis.observableSummary.map((item, idx) => (
              <li key={idx}>{cleanDisplayText(item)}</li>
            ))}
          </ul>
        </div>
      )}

      {analysis.methodologies && analysis.methodologies.length > 0 && (
        <div className="cti-threat-landscape">
          <h3 className="cti-section-title" style={{ fontSize: '1rem', marginBottom: '0.5rem' }}>Methodologies Applied</h3>
          <ul>
            {analysis.methodologies.map((item, idx) => (
              <li key={idx}>{cleanDisplayText(item)}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Temporal Patterns - THE CORE VALUE */}
      {analysis.temporalPatterns && analysis.temporalPatterns.length > 0 && (
        <div className="cti-analysis-section cti-correlation-primary">
          <button 
            className="cti-section-toggle"
            onClick={() => toggleSection('patterns')}
          >
            <span>⏱️ Temporal Correlation ({analysis.temporalPatterns.length})</span>
            <span className="cti-toggle-icon">{expandedSections.has('patterns') ? '▼' : '▶'}</span>
          </button>
          
          {expandedSections.has('patterns') && (
            <div className="cti-patterns-list">
              {analysis.temporalPatterns.map((pattern, i) => (
                <div key={i} className="cti-pattern-card">
                  <div className="cti-pattern-header">
                    <span className="cti-pattern-name">{pattern.pattern}</span>
                    <span className="cti-pattern-timeframe">{pattern.timeframe}</span>
                  </div>
                  <p className="cti-pattern-desc">{cleanDisplayText(pattern.description)}</p>
                  {pattern.evidence && pattern.evidence.length > 0 && (
                    <div className="cti-pattern-evidence">
                      <span className="cti-evidence-label">Evidence:</span>
                      {pattern.evidence.map((ev, j) => (
                        <a
                          key={j}
                          href={ev.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="cti-evidence-link-inline"
                        >
                          [{ev.source}] {cleanDisplayText(ev.excerpt).substring(0, 60)}... ↗
                        </a>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Cross-Source Correlations */}
      {analysis.crossSourceLinks && analysis.crossSourceLinks.length > 0 && (
        <div className="cti-analysis-section">
          <button 
            className="cti-section-toggle"
            onClick={() => toggleSection('cross')}
          >
            <span>🔗 Infrastructure ↔ Social Links ({analysis.crossSourceLinks.length})</span>
            <span className="cti-toggle-icon">{expandedSections.has('cross') ? '▼' : '▶'}</span>
          </button>
          
          {expandedSections.has('cross') && (
            <div className="cti-cross-links">
              {analysis.crossSourceLinks.map((link, i) => (
                <div key={i} className="cti-cross-link-card">
                  <div className="cti-cross-signals">
                    <div className="cti-cross-infra">
                      <span className="cti-cross-label">🖥️ Infrastructure</span>
                      <span className="cti-cross-value">{cleanDisplayText(link.infraSignal)}</span>
                    </div>
                    <div className="cti-cross-connector">
                      <span className="cti-cross-delta">{cleanDisplayText(link.timeDelta)}</span>
                      <span className="cti-cross-arrow">⟷</span>
                    </div>
                    <div className="cti-cross-social">
                      <span className="cti-cross-label">💬 Social</span>
                      <span className="cti-cross-value">{cleanDisplayText(link.socialSignal)}</span>
                    </div>
                  </div>
                  <p className="cti-cross-relationship">{cleanDisplayText(link.relationship)}</p>
                  <p className="cti-cross-significance">{cleanDisplayText(link.significance)}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TTPs Section - Relevant techniques */}
      {analysis.ttps && analysis.ttps.length > 0 && (
        <div className="cti-analysis-section">
          <button 
            className="cti-section-toggle"
            onClick={() => toggleSection('ttps')}
          >
            <span>⚔️ Observed TTPs ({analysis.ttps.length})</span>
            <span className="cti-toggle-icon">{expandedSections.has('ttps') ? '▼' : '▶'}</span>
          </button>
          
          {expandedSections.has('ttps') && (
            <div className="cti-ttps-list">
              {analysis.ttps.map((ttp, i) => (
                <a
                  key={i}
                  href={`https://attack.mitre.org/techniques/${ttp.techniqueId}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="cti-ttp-card"
                >
                  <div className="cti-ttp-header">
                    <span className="cti-ttp-id">{ttp.techniqueId}</span>
                    <span className="cti-ttp-tactic">{ttp.tactic}</span>
                  </div>
                  <p className="cti-ttp-name">{ttp.technique}</p>
                  {ttp.evidence && (
                    <p className="cti-ttp-evidence">{cleanDisplayText(ttp.evidence)}</p>
                  )}
                  <span className="cti-ttp-link-icon">↗</span>
                </a>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Sources and References */}
      {analysis.sourcesAndReferences && analysis.sourcesAndReferences.length > 0 && (
        <div className="cti-sources-refs">
          <h4>📚 Sources & References</h4>
          <div className="cti-refs-list">
            {analysis.sourcesAndReferences.map((ref, i) => (
              <a
                key={i}
                href={ref.url}
                target="_blank"
                rel="noopener noreferrer"
                className="cti-ref-link"
              >
                <span className="cti-ref-source">{ref.source}</span>
                <span className="cti-ref-relevance">{ref.relevance}</span>
                <span className="cti-ref-arrow">↗</span>
              </a>
            ))}
          </div>
        </div>
      )}
    </section>
  );
};

const Footer: React.FC<{ generatedAt?: string; onRefresh?: () => void; isRefreshing?: boolean }> = ({ 
  generatedAt, 
  onRefresh, 
  isRefreshing 
}) => (
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
        {onRefresh && (
          <button 
            className="cti-refresh-btn" 
            onClick={onRefresh}
            disabled={isRefreshing}
            title="Refresh data"
          >
            {isRefreshing ? '⟳' : '↻'} Refresh
          </button>
        )}
        <span className="cti-footer-brand">Powered by Hackfluency Intelligence</span>
      </div>
    </div>
  </footer>
);

export default CTIDashboard;
