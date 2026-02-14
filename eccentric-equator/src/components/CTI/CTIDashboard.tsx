/**
 * CTI Dashboard v2.0 - Security Intelligence Visualization
 * 3-Column Grid Layout with Interactive Concept Mapping
 */

import React, { useEffect, useState, useCallback } from 'react';
import './cti-dashboard.css';

// Import new modular components
import LeftPanel from './LeftPanel';
import RightPanel from './RightPanel';
import MITREOverlay from './MITREOverlay';
import RecommendationsPanel from './RecommendationsPanel';
import HistoricalPanel from './HistoricalPanel';
import MetricsGrid from './MetricsGrid';

// Types
interface DashboardData {
  meta: { version: string; generatedAt: string; validUntil: string };
  status: { riskLevel: string; riskScore: number; trend: string; confidenceLevel: number };
  executive: { headline: string; summary: string; keyFindings: string[]; recommendedActions: string[] };
  metrics: { totalSignals: number; criticalCount: number; highCount: number; mediumCount: number; lowCount: number; categories: Array<{ name: string; count: number; percentage: number }> };
  timeline: Array<{ id: string; title: string; severity: string; category: string; timestamp: string }>;
  sources: Array<{ name: string; signalCount: number; lastUpdate: string }>;
  indicators: { cves: string[]; domains: string[]; ips: string[]; keywords: string[] };
  infrastructure?: { totalHosts: number; exposedPorts: Array<{ port: number; service: string; count: number; percentage: number }>; topCountries: Array<{ country: string; count: number }>; vulnerableHosts: number };
  socialIntel?: { totalPosts: number; themes: string[]; tone: string; topPosts: Array<{ excerpt: string; author: string; engagement: number; url?: string }> };
  ctiAnalysis?: { model: string; killChainPhase: string; threatLandscape: string; analystBrief?: string; methodologies?: string[]; ttps?: Array<{ technique: string; techniqueId: string; tactic: string; evidence: string; confidence: number }>; mitreAttack?: Array<{ tactic: string; techniques: string[]; mitigations: string[] }> };
  assessmentLayer?: { correlation: { score: number; strength: string; explanation: string }; narrative: string; iocStats: { uniqueCVECount: number; uniqueDomainCount: number; uniqueIPCount: number; totalIndicators: number }; baselineComparison?: { previousRiskScore: number; currentRiskScore: number; delta: number; trendDirection: string } };
  modelMetadata?: { strategic: string; technical: string };
}

const RISK_COLORS: Record<string, string> = {
  critical: '#E31B23',
  elevated: '#FF6B35',
  moderate: '#FFB800',
  low: '#00D26A'
};

const CTIDashboard: React.FC = () => {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Overlay states
  const [mitreOpen, setMitreOpen] = useState(false);
  const [recommendationsOpen, setRecommendationsOpen] = useState(false);
  
  // Interactive concept mapping
  const [highlightedConcept, setHighlightedConcept] = useState<string | null>(null);

  // Load dashboard data
  useEffect(() => {
    loadDashboard();
  }, []);

  const loadDashboard = async () => {
    try {
      const response = await fetch(`/data/cti-dashboard.json?_cb=${Date.now()}`);
      if (!response.ok) throw new Error('Dashboard data not available');
      const dashboardData = await response.json();
      setData(dashboardData);
      setError(null);
    } catch (err) {
      setError('Intelligence data currently unavailable');
      console.error('Failed to load CTI dashboard:', err);
    } finally {
      setLoading(false);
    }
  };

  // Handle concept click for interactive mapping
  const handleConceptClick = useCallback((concept: string) => {
    setHighlightedConcept(prev => prev === concept ? null : concept);
  }, []);

  // Loading state
  if (loading) {
    return (
      <div className="cti-loading">
        <div className="cti-loading-spinner" />
        <span>Loading Intelligence Data...</span>
      </div>
    );
  }

  // Error state
  if (error || !data) {
    return (
      <div className="cti-container">
        <div className="cti-error">
          <div className="cti-error-icon">⚠</div>
          <h3>Intelligence Feed Unavailable</h3>
          <p>{error || 'Threat data is being collected. Check back shortly.'}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="cti-container">
      {/* Main Layout - 3 Column Grid */}
      <div className="cti-layout">
        
        {/* Header */}
        <header className="cti-main-header">
          <div className="cti-header-left">
            <div className="cti-logo">
              <span className="cti-logo-icon">◆</span>
              <span className="cti-logo-text">HACKFLUENCY</span>
            </div>
            <div>
              <h1 className="cti-header-title">Threat Intelligence Correlation</h1>
              <p className="cti-header-subtitle">Context-aware analysis: Social signals → Infrastructure exposure</p>
            </div>
          </div>
          
          {/* Action Buttons */}
          <div className="cti-header-actions">
            <button 
              className={`cti-toggle-button ${mitreOpen ? 'active' : ''}`}
              onClick={() => setMitreOpen(true)}
            >
              <span>🎯</span>
              <span>MITRE Matrix</span>
            </button>
            <button 
              className={`cti-toggle-button ${recommendationsOpen ? 'active' : ''}`}
              onClick={() => setRecommendationsOpen(true)}
            >
              <span>🛡️</span>
              <span>Mitigations</span>
            </button>
          </div>
        </header>

        {/* LEFT PANEL - Technical IoCs */}
        <LeftPanel 
          indicators={data.indicators}
          infrastructure={data.infrastructure}
          iocStats={data.assessmentLayer?.iocStats}
          highlightedConcept={highlightedConcept}
          onConceptClick={handleConceptClick}
        />

        {/* CENTER PANEL - Analysis & Concepts */}
        <main className="cti-center-panel">
          {/* Risk Banner */}
          <div className="cti-risk-mini">
            <div 
              className="cti-risk-circle-mini"
              style={{ 
                background: `conic-gradient(${RISK_COLORS[data.status.riskLevel]} ${data.status.riskScore * 3.6}deg, #2a2a2a ${data.status.riskScore * 3.6}deg)`
              }}
            >
              <span className="cti-risk-score-mini">{data.status.riskScore}</span>
            </div>
            <div className="cti-risk-info-mini">
              <div className="cti-risk-level-mini" style={{ color: RISK_COLORS[data.status.riskLevel] }}>
                {data.status.riskLevel.toUpperCase()} RISK
              </div>
              <div className="cti-risk-meta-mini">
                <span>Confidence: {data.status.confidenceLevel}%</span>
                <span>Trend: {data.status.trend}</span>
                <span>Valid until: {new Date(data.meta.validUntil).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}</span>
              </div>
            </div>
          </div>

          {/* Metrics Grid - Severity Distribution */}
          <MetricsGrid metrics={data.metrics} />

          {/* Executive Summary */}
          <div className="cti-analysis-summary">
            <h3>
              <span>📋</span>
              {data.executive.headline}
            </h3>
            <p className="cti-analysis-text">
              {data.executive.summary.replace(/\*\*/g, '')}
            </p>
          </div>

          {/* Concept Nodes - Interactive */}
          {data.assessmentLayer && (
            <div className="cti-concept-section">
              <h3>
                <span>🔗</span>
                Key Concepts
              </h3>
              <div className="cti-concept-nodes">
                {data.indicators.keywords.map((keyword, i) => (
                  <button
                    key={i}
                    className={`cti-concept-node ${highlightedConcept === keyword ? 'selected' : ''}`}
                    onClick={() => handleConceptClick(keyword)}
                  >
                    {keyword}
                  </button>
                ))}
                {data.indicators.cves.map((cve, i) => (
                  <button
                    key={`cve-${i}`}
                    className={`cti-concept-node ${highlightedConcept === cve ? 'selected' : ''}`}
                    onClick={() => handleConceptClick(cve)}
                  >
                    {cve}
                  </button>
                ))}
                <button
                  className={`cti-concept-node ${highlightedConcept === 'opportunistic' ? 'selected' : ''}`}
                  onClick={() => handleConceptClick('opportunistic')}
                >
                  Opportunistic
                </button>
              </div>
            </div>
          )}

          {/* Correlation Visualization */}
          {data.assessmentLayer && (
            <div className="cti-correlation-viz">
              <h3>
                <span>📊</span>
                Correlation Strength
              </h3>
              <div className="cti-correlation-bar">
                <span className="cti-correlation-label">Overall</span>
                <div className="cti-correlation-track">
                  <div 
                    className={`cti-correlation-fill ${data.assessmentLayer.correlation.strength}`}
                    style={{ width: `${data.assessmentLayer.correlation.score * 100}%` }}
                  />
                </div>
                <span className="cti-correlation-value">
                  {Math.round(data.assessmentLayer.correlation.score * 100)}%
                </span>
              </div>
              <p className="cti-analysis-text" style={{ fontSize: '12px', color: '#888' }}>
                {data.assessmentLayer.correlation.explanation}
              </p>
            </div>
          )}

          {/* Assessment Narrative */}
          {data.assessmentLayer && (
            <div className="cti-why-panel">
              <div className="cti-why-header">
                <span className="cti-why-icon">💡</span>
                <span className="cti-why-title">Analyst Assessment</span>
              </div>
              <p className="cti-why-content">{data.assessmentLayer.narrative}</p>
            </div>
          )}

          {/* Methodology */}
          {data.ctiAnalysis?.methodologies && (
            <div className="cti-section-card">
              <div className="cti-section-header">
                <span className="cti-section-icon">🔬</span>
                <h4>Methodologies Applied</h4>
              </div>
              <ul style={{ margin: 0, paddingLeft: '20px', fontSize: '12px', color: '#888' }}>
                {data.ctiAnalysis.methodologies.map((m, i) => (
                  <li key={i} style={{ marginBottom: '4px' }}>{m}</li>
                ))}
              </ul>
            </div>
          )}
        </main>

        {/* RIGHT PANEL - Social Intel */}
        <RightPanel 
          socialIntel={data.socialIntel}
          keywords={data.indicators.keywords}
          highlightedConcept={highlightedConcept}
          onConceptClick={handleConceptClick}
        />

        {/* BOTTOM PANEL - Historical Data */}
        <HistoricalPanel 
          timeline={data.timeline}
          sources={data.sources}
          baselineComparison={data.assessmentLayer?.baselineComparison}
        />

      </div>

      {/* Overlays */}
      <MITREOverlay 
        isOpen={mitreOpen}
        onClose={() => setMitreOpen(false)}
        mitreAttack={data.ctiAnalysis?.mitreAttack}
        ttps={data.ctiAnalysis?.ttps}
      />

      <RecommendationsPanel 
        isOpen={recommendationsOpen}
        onClose={() => setRecommendationsOpen(false)}
        recommendations={{
          immediate: data.executive.recommendedActions.slice(0, 2),
          strategic: data.executive.recommendedActions.slice(2),
          rationale: {}
        }}
      />

      {/* Footer */}
      <footer className="cti-footer">
        <div className="cti-footer-content">
          <p className="cti-footer-disclaimer">
            This intelligence dashboard presents aggregated threat signals from public sources. 
            Data is collected and analyzed automatically. Findings should be validated before operational decisions.
          </p>
          <div className="cti-footer-meta">
            <span>Last updated: {new Date(data.meta.generatedAt).toLocaleString('en-US', { 
              month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' 
            })}</span>
            <span className="cti-footer-brand">Powered by Hackfluency Intelligence</span>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default CTIDashboard;
