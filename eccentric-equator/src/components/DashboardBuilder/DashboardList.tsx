import React, { useState, useEffect, useCallback } from 'react';
import { AuthWrapper } from '../Auth';
import './list-styles.css';
import type { SavedDashboard } from './dashboardStorage';
import {
  getAllDashboards,
  archiveDashboard,
  restoreDashboard,
  deleteDashboard,
  duplicateDashboard,
} from './dashboardStorage';

type ViewMode = 'active' | 'archived';

const DashboardList: React.FC = () => {
  const [dashboards, setDashboards] = useState<SavedDashboard[]>([]);
  const [viewMode, setViewMode] = useState<ViewMode>('active');
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);

  const loadDashboards = useCallback(() => {
    const all = getAllDashboards();
    setDashboards(all);
  }, []);

  useEffect(() => {
    loadDashboards();
  }, [loadDashboards]);

  const filteredDashboards = dashboards.filter((d) =>
    viewMode === 'archived' ? d.status === 'archived' : d.status !== 'archived'
  );

  const handleArchive = (id: string) => {
    archiveDashboard(id);
    loadDashboards();
  };

  const handleRestore = (id: string) => {
    restoreDashboard(id);
    loadDashboards();
  };

  const handleDelete = (id: string) => {
    if (deleteConfirm === id) {
      deleteDashboard(id);
      setDeleteConfirm(null);
      loadDashboards();
    } else {
      setDeleteConfirm(id);
      // Auto-reset after 3 seconds
      setTimeout(() => setDeleteConfirm(null), 3000);
    }
  };

  const handleDuplicate = (id: string) => {
    duplicateDashboard(id);
    loadDashboards();
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  };

  const getStatusColor = (status: SavedDashboard['status']) => {
    switch (status) {
      case 'published': return '#00D26A';
      case 'draft': return '#6a6a6a';
      case 'archived': return '#ef4444';
      default: return '#6a6a6a';
    }
  };

  return (
    <AuthWrapper>
      <div className="dashboard-list-page">
        {/* Navigation */}
      <nav className="list-nav">
        <div className="nav-brand">
          <a href="/">
            <img src="/HFNeon.png" alt="Hackfluency" />
            <span className="logo-text">
              <span className="logo-hack">Hack</span>
              <span className="logo-fluency">fluency</span>
            </span>
          </a>
          <span className="nav-divider" />
          <span className="nav-title">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="3" y="3" width="7" height="7" rx="1"/>
              <rect x="14" y="3" width="7" height="7" rx="1"/>
              <rect x="3" y="14" width="7" height="7" rx="1"/>
              <rect x="14" y="14" width="7" height="7" rx="1"/>
            </svg>
            All Dashboards
          </span>
        </div>
        <div className="nav-actions">
          <a href="/dashboard-builder" className="nav-btn primary">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
            </svg>
            <span>New</span>
          </a>
        </div>
      </nav>

      {/* Main Content */}
      <main className="list-content">
        {/* Header */}
        <header className="list-header">
          <div className="list-header-info">
            <h1>Strategy Dashboards</h1>
            <p>Manage and view your security strategy dashboards</p>
          </div>
          <div className="list-tabs">
            <button
              className={`tab-btn ${viewMode === 'active' ? 'active' : ''}`}
              onClick={() => setViewMode('active')}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/>
              </svg>
              Active
              <span className="tab-count">
                {dashboards.filter((d) => d.status !== 'archived').length}
              </span>
            </button>
            <button
              className={`tab-btn ${viewMode === 'archived' ? 'active' : ''}`}
              onClick={() => setViewMode('archived')}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 8v13H3V8M1 3h22v5H1zM10 12h4"/>
              </svg>
              Archived
              <span className="tab-count">
                {dashboards.filter((d) => d.status === 'archived').length}
              </span>
            </button>
          </div>
        </header>

        {/* Dashboard Grid */}
        {filteredDashboards.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">
              {viewMode === 'archived' ? (
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <path d="M21 8v13H3V8M1 3h22v5H1zM10 12h4"/>
                </svg>
              ) : (
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <rect x="3" y="3" width="18" height="18" rx="2"/>
                  <line x1="12" y1="8" x2="12" y2="16"/>
                  <line x1="8" y1="12" x2="16" y2="12"/>
                </svg>
              )}
            </div>
            <h3>{viewMode === 'archived' ? 'No archived dashboards' : 'No dashboards yet'}</h3>
            <p>
              {viewMode === 'archived'
                ? 'Archived dashboards will appear here'
                : 'Create your first strategy dashboard to get started'}
            </p>
            {viewMode === 'active' && (
              <a href="/dashboard-builder" className="empty-cta">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
                </svg>
                Create Dashboard
              </a>
            )}
          </div>
        ) : (
          <div className="dashboard-grid">
            {filteredDashboards.map((dashboard) => (
              <article key={dashboard.id} className="dashboard-card">
                <div className="card-header">
                  <span
                    className="card-status"
                    style={{ '--status-color': getStatusColor(dashboard.status) } as React.CSSProperties}
                  >
                    {dashboard.status}
                  </span>
                  <span className="card-version">v{dashboard.version}</span>
                </div>

                <h3 className="card-title">{dashboard.name}</h3>
                
                {dashboard.description && (
                  <p className="card-description">{dashboard.description}</p>
                )}

                <div className="card-meta">
                  <div className="card-stat">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/>
                      <rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/>
                    </svg>
                    {dashboard.nodes.length} items
                  </div>
                  <div className="card-stat">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M5 12h14M12 5l7 7-7 7"/>
                    </svg>
                    {dashboard.edges.length} connections
                  </div>
                </div>

                <div className="card-dates">
                  <span>Created: {formatDate(dashboard.createdAt)}</span>
                  {dashboard.publishedAt && (
                    <span>Published: {formatDate(dashboard.publishedAt)}</span>
                  )}
                </div>

                  <div className="card-actions">
                    {dashboard.status !== 'archived' ? (
                      <>
                        <a href={`/dashboards/view?id=${dashboard.id}`} className="action-btn primary">
                          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                          <circle cx="12" cy="12" r="3"/>
                        </svg>
                        View
                      </a>
                      <button
                        className="action-btn"
                        onClick={() => handleDuplicate(dashboard.id)}
                        title="Duplicate"
                      >
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <rect x="9" y="9" width="13" height="13" rx="2"/>
                          <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
                        </svg>
                      </button>
                      <button
                        className="action-btn archive"
                        onClick={() => handleArchive(dashboard.id)}
                        title="Archive"
                      >
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M21 8v13H3V8M1 3h22v5H1zM10 12h4"/>
                        </svg>
                      </button>
                    </>
                  ) : (
                    <>
                      <button
                        className="action-btn restore"
                        onClick={() => handleRestore(dashboard.id)}
                      >
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M3 12a9 9 0 019-9 9.75 9.75 0 016.74 2.74L21 8"/>
                          <path d="M21 3v5h-5"/>
                          <path d="M21 12a9 9 0 01-9 9 9.75 9.75 0 01-6.74-2.74L3 16"/>
                          <path d="M8 16H3v5"/>
                        </svg>
                        Restore
                      </button>
                      <button
                        className={`action-btn delete ${deleteConfirm === dashboard.id ? 'confirm' : ''}`}
                        onClick={() => handleDelete(dashboard.id)}
                        title={deleteConfirm === dashboard.id ? 'Click again to confirm' : 'Delete permanently'}
                      >
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
                        </svg>
                        {deleteConfirm === dashboard.id ? 'Confirm' : 'Delete'}
                      </button>
                    </>
                  )}
                </div>
              </article>
            ))}
          </div>
        )}
      </main>
      </div>
    </AuthWrapper>
  );
};

export default DashboardList;
