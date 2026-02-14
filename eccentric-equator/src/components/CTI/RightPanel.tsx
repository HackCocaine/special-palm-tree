/**
 * RightPanel - Social Intelligence Display
 * Shows themes, posts, tone from social media sources
 */

import React from 'react';
import './cti-dashboard.css';

interface RightPanelProps {
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
  keywords?: string[];
  highlightedConcept?: string | null;
  onConceptClick?: (concept: string) => void;
}

const RightPanel: React.FC<RightPanelProps> = ({
  socialIntel,
  keywords,
  highlightedConcept,
  onConceptClick
}) => {
  const isHighlighted = (concept: string) => highlightedConcept === concept;

  const toneColors: Record<string, { bg: string; text: string; border: string }> = {
    confirmed: { bg: 'rgba(227, 27, 35, 0.1)', text: '#FF6B6B', border: 'rgba(227, 27, 35, 0.3)' },
    mixed: { bg: 'rgba(255, 184, 0, 0.1)', text: '#FFB800', border: 'rgba(255, 184, 0, 0.3)' },
    speculative: { bg: 'rgba(0, 210, 106, 0.1)', text: '#00D26A', border: 'rgba(0, 210, 106, 0.3)' }
  };

  const toneConfig = toneColors[socialIntel?.tone || 'speculative'];

  return (
    <div className="cti-right-panel">
      {/* Header */}
      <div className="cti-panel-header">
        <h3 className="cti-panel-title">
          <span className="cti-panel-icon">💬</span>
          Social Intelligence
        </h3>
      </div>

      {/* Summary Stats */}
      {socialIntel && (
        <div className="cti-social-summary">
          <div className="cti-social-stat">
            <span className="cti-social-stat-value">{socialIntel.totalPosts}</span>
            <span className="cti-social-stat-label">Posts Analyzed</span>
          </div>
          <div 
            className="cti-social-tone"
            style={{ 
              background: toneConfig.bg,
              color: toneConfig.text,
              borderColor: toneConfig.border
            }}
          >
            <span className="cti-tone-icon">
              {socialIntel.tone === 'confirmed' ? '🔴' : 
               socialIntel.tone === 'mixed' ? '🟡' : '🟢'}
            </span>
            <span className="cti-tone-text">{socialIntel.tone}</span>
          </div>
        </div>
      )}

      {/* Themes Section */}
      {socialIntel?.themes && socialIntel.themes.length > 0 && (
        <div className="cti-section-card">
          <div className="cti-section-header">
            <span className="cti-section-icon">🔥</span>
            <h4>Detected Themes</h4>
          </div>
          <div className="cti-theme-cloud">
            {socialIntel.themes.map((theme, i) => (
              <button
                key={i}
                className={`cti-theme-chip ${isHighlighted(theme) ? 'highlighted' : ''}`}
                onClick={() => onConceptClick?.(theme)}
              >
                {theme}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Top Discussions */}
      {socialIntel?.topPosts && socialIntel.topPosts.length > 0 && (
        <div className="cti-section-card">
          <div className="cti-section-header">
            <span className="cti-section-icon">📈</span>
            <h4>Top Discussions</h4>
          </div>
          <div className="cti-posts-list">
            {socialIntel.topPosts.slice(0, 5).map((post, i) => (
              <div 
                key={i} 
                className={`cti-post-item ${isHighlighted(post.author) ? 'cti-highlight-right' : ''}`}
                onClick={() => onConceptClick?.(post.author)}
              >
                <div className="cti-post-header">
                  <span className="cti-post-author">@{post.author}</span>
                  <span className="cti-post-engagement">
                    ❤️ {post.engagement}
                  </span>
                </div>
                <p className="cti-post-excerpt">
                  {post.excerpt.length > 100 
                    ? `${post.excerpt.substring(0, 100)}...` 
                    : post.excerpt}
                </p>
                {post.url && (
                  <a 
                    href={post.url} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="cti-post-link"
                    onClick={(e) => e.stopPropagation()}
                  >
                    View on X ↗
                  </a>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Keywords from Social */}
      {keywords && keywords.length > 0 && (
        <div className="cti-section-card">
          <div className="cti-section-header">
            <span className="cti-section-icon">🔑</span>
            <h4>Trending Keywords</h4>
          </div>
          <div className="cti-keyword-cloud">
            {keywords.map((keyword, i) => (
              <button
                key={i}
                className={`cti-keyword-chip ${isHighlighted(keyword) ? 'highlighted' : ''}`}
                onClick={() => onConceptClick?.(keyword)}
                style={{
                  '--chip-bg': 'rgba(29, 155, 240, 0.1)',
                  '--chip-border': 'rgba(29, 155, 240, 0.2)',
                  '--chip-color': '#1D9BF0'
                } as React.CSSProperties}
              >
                {keyword}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Source Attribution */}
      <div className="cti-panel-footer">
        <span>Data from X.com</span>
      </div>
    </div>
  );
};

export default RightPanel;
