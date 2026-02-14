/**
 * LeftPanel - Technical IoCs Display
 * Shows CVEs, IPs, Domains, Keywords, Infrastructure data
 * Connected to interactive concept mapping
 */

import React from 'react';
import './cti-dashboard.css';

interface LeftPanelProps {
  indicators: {
    cves: string[];
    domains: string[];
    ips: string[];
    keywords: string[];
  };
  infrastructure?: {
    totalHosts: number;
    exposedPorts: Array<{ port: number; service: string; count: number; percentage: number }>;
    topCountries: Array<{ country: string; count: number }>;
    vulnerableHosts: number;
  };
  iocStats?: {
    uniqueCVECount: number;
    uniqueDomainCount: number;
    uniqueIPCount: number;
    totalIndicators: number;
  };
  highlightedConcept?: string | null;
  onConceptClick?: (concept: string) => void;
}

const LeftPanel: React.FC<LeftPanelProps> = ({
  indicators,
  infrastructure,
  iocStats,
  highlightedConcept,
  onConceptClick
}) => {
  const isHighlighted = (concept: string) => highlightedConcept === concept;

  return (
    <div className="cti-left-panel">
      {/* Header */}
      <div className="cti-panel-header">
        <h3 className="cti-panel-title">
          <span className="cti-panel-icon">🔬</span>
          Technical Intelligence
        </h3>
      </div>

      {/* IoC Statistics Summary */}
      {iocStats && (
        <div className="cti-ioc-summary">
          <div className="cti-ioc-stat">
            <span className="cti-ioc-stat-value">{iocStats.totalIndicators}</span>
            <span className="cti-ioc-stat-label">Total Indicators</span>
          </div>
          <div className="cti-ioc-stat-breakdown">
            <span className={isHighlighted('CVE') ? 'highlighted' : ''}>
              {iocStats.uniqueCVECount} CVEs
            </span>
            <span className={isHighlighted('domain') ? 'highlighted' : ''}>
              {iocStats.uniqueDomainCount} Domains
            </span>
            <span className={isHighlighted('IP') ? 'highlighted' : ''}>
              {iocStats.uniqueIPCount} IPs
            </span>
          </div>
        </div>
      )}

      {/* CVEs Section */}
      {indicators.cves.length > 0 && (
        <div className={`cti-section-card ${isHighlighted('CVE') ? 'cti-highlight-left' : ''}`}>
          <div className="cti-section-header">
            <span className="cti-section-icon">🐛</span>
            <h4>CVEs ({indicators.cves.length})</h4>
          </div>
          <div className="cti-tag-list">
            {indicators.cves.map((cve, i) => (
              <button
                key={i}
                className="cti-tag cve-tag"
                onClick={() => onConceptClick?.(cve)}
              >
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={(e) => e.stopPropagation()}
                >
                  {cve}
                </a>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Domains Section */}
      {indicators.domains.length > 0 && (
        <div className={`cti-section-card ${isHighlighted('domain') ? 'cti-highlight-left' : ''}`}>
          <div className="cti-section-header">
            <span className="cti-section-icon">🌐</span>
            <h4>Domains ({indicators.domains.length})</h4>
          </div>
          <div className="cti-domain-list">
            {indicators.domains.slice(0, 8).map((domain, i) => (
              <button
                key={i}
                className="cti-domain-item"
                onClick={() => onConceptClick?.(domain)}
              >
                <span className="cti-domain-icon">🔗</span>
                <span className="cti-domain-name">{domain}</span>
              </button>
            ))}
            {indicators.domains.length > 8 && (
              <button className="cti-more-button">
                +{indicators.domains.length - 8} more
              </button>
            )}
          </div>
        </div>
      )}

      {/* IPs Section */}
      {indicators.ips.length > 0 && (
        <div className={`cti-section-card ${isHighlighted('IP') ? 'cti-highlight-left' : ''}`}>
          <div className="cti-section-header">
            <span className="cti-section-icon">📡</span>
            <h4>IP Addresses ({indicators.ips.length})</h4>
          </div>
          <div className="cti-ip-list">
            {indicators.ips.map((ip, i) => (
              <button
                key={i}
                className="cti-ip-item"
                onClick={() => onConceptClick?.(ip)}
              >
                <code className="cti-ip-code">{ip}</code>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Keywords Section */}
      {indicators.keywords.length > 0 && (
        <div className="cti-section-card">
          <div className="cti-section-header">
            <span className="cti-section-icon">🔑</span>
            <h4>Keywords</h4>
          </div>
          <div className="cti-keyword-cloud">
            {indicators.keywords.map((keyword, i) => (
              <button
                key={i}
                className={`cti-keyword-chip ${isHighlighted(keyword) ? 'highlighted' : ''}`}
                onClick={() => onConceptClick?.(keyword)}
              >
                {keyword}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Infrastructure Summary */}
      <div className="cti-section-card">
        <div className="cti-section-header">
          <span className="cti-section-icon">🖥️</span>
          <h4>Infrastructure</h4>
        </div>
        <div className="cti-infra-stats">
          <div className="cti-infra-stat">
            <span className="cti-infra-stat-value">{infrastructure?.totalHosts || 0}</span>
            <span className="cti-infra-stat-label">Exposed Hosts</span>
          </div>
          <div className="cti-infra-stat">
            <span className="cti-infra-stat-value">{infrastructure?.vulnerableHosts || 0}</span>
            <span className="cti-infra-stat-label">Vulnerable</span>
          </div>
        </div>
        
        {infrastructure?.exposedPorts && infrastructure.exposedPorts.length > 0 && (
          <div className="cti-ports-list">
            <h5>Exposed Services</h5>
            {infrastructure.exposedPorts.slice(0, 4).map((port, i) => (
              <div key={i} className="cti-port-item">
                <span className="cti-port-number">{port.port}</span>
                <span className="cti-port-service">{port.service}</span>
                <div className="cti-port-bar">
                  <div 
                    className="cti-port-fill" 
                    style={{ width: `${port.percentage}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        )}

        {(!infrastructure?.totalHosts || infrastructure.totalHosts === 0) && (
          <div className="cti-infra-clean">
            <span className="cti-clean-icon">✅</span>
            <span className="cti-clean-text">No exposed infrastructure detected</span>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="cti-panel-footer">
        <span>Data from Shodan, NVD</span>
      </div>
    </div>
  );
};

export default LeftPanel;
