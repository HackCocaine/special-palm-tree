import React, { useMemo, useCallback, useState, useRef, useEffect } from 'react';
import {
  ReactFlow,
  Controls,
  Background,
  MiniMap,
  BackgroundVariant,
  type Edge,
  type Node,
  type NodeTypes,
  type ReactFlowInstance,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import './viewer-styles.css';

import StrategyNode from './StrategyNode';
import type { StrategyNodeData, Quarter } from './types';
import { CATEGORY_CONFIG, QUARTER_CONFIG } from './types';
import type { SavedDashboard } from './dashboardStorage';
import { exportDashboardToPDF } from './pdfExport';

const nodeTypes: NodeTypes = {
  strategy: StrategyNode,
};

interface DashboardViewerProps {
  dashboard: SavedDashboard;
}

// Quarter column overlay for viewer - now fully flexible
const QuarterColumnsViewer: React.FC = () => (
  <div className="viewer-quarter-columns">
    {(['q1', 'q2', 'q3', 'q4'] as Quarter[]).map((q) => (
      <div 
        key={q} 
        className="viewer-quarter-column"
      >
        <div className="viewer-quarter-label">
          <span className={`viewer-quarter-badge ${q}`}>{QUARTER_CONFIG[q].label}</span>
          <span className="viewer-quarter-name">{QUARTER_CONFIG[q].months}</span>
        </div>
      </div>
    ))}
  </div>
);

// Dashboard stats
const DashboardStats: React.FC<{ nodes: Node<StrategyNodeData>[] }> = ({ nodes }) => {
  const stats = useMemo(() => {
    const byCategory: Record<string, number> = {};
    const byStatus: Record<string, number> = { done: 0, active: 0, planned: 0, blocked: 0 };
    
    nodes.forEach((node) => {
      const data = node.data as StrategyNodeData;
      byCategory[data.category] = (byCategory[data.category] || 0) + 1;
      byStatus[data.status] = (byStatus[data.status] || 0) + 1;
    });
    
    return { byCategory, byStatus, total: nodes.length };
  }, [nodes]);

  const progressPercent = stats.total > 0 
    ? Math.round((stats.byStatus.done / stats.total) * 100) 
    : 0;

  return (
    <div className="viewer-stats">
      <div className="stat-card">
        <div className="stat-value">{stats.total}</div>
        <div className="stat-label">Total Items</div>
      </div>
      <div className="stat-card progress">
        <div className="stat-value">{progressPercent}%</div>
        <div className="stat-label">Complete</div>
        <div className="stat-bar">
          <div className="stat-bar-fill" style={{ width: `${progressPercent}%` }} />
        </div>
      </div>
      <div className="stat-card">
        <div className="stat-value">{stats.byStatus.active}</div>
        <div className="stat-label">In Progress</div>
      </div>
      <div className="stat-card">
        <div className="stat-value">{stats.byStatus.blocked}</div>
        <div className="stat-label">Blocked</div>
      </div>
    </div>
  );
};

const DashboardViewer: React.FC<DashboardViewerProps> = ({ dashboard }) => {
  const [isExporting, setIsExporting] = useState(false);
  const canvasRef = useRef<HTMLDivElement>(null);
  const [canvasWidth, setCanvasWidth] = useState(0);

  // --- DYNAMIC LAYOUT LOGIC ---
  const BASE_CANVAS_WIDTH = 1200; // The width the saved node positions were based on

  // 1. Observe canvas size and update state
  useEffect(() => {
    const canvasElement = canvasRef.current;
    if (!canvasElement) return;

    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (entry) {
        setCanvasWidth(entry.contentRect.width);
      }
    });

    observer.observe(canvasElement);
    setCanvasWidth(canvasElement.offsetWidth); // Set initial width

    return () => observer.disconnect();
  }, []);
  
  // 2. Scale node positions and widths based on current canvas size
  const scaledNodes = useMemo(() => {
    if (!canvasWidth || canvasWidth === BASE_CANVAS_WIDTH) {
      return dashboard.nodes;
    }
    const scale = canvasWidth / BASE_CANVAS_WIDTH;
    return dashboard.nodes.map(node => ({
      ...node,
      position: {
        x: node.position.x * scale,
        y: node.position.y, // y position remains the same
      },
      width: node.width ? node.width * scale : undefined,
    }));
  }, [dashboard.nodes, canvasWidth]);

  // Handle React Flow initialization
  const onInit = useCallback((instance: ReactFlowInstance) => {
    setTimeout(() => {
      instance.fitView({ padding: 0.1, duration: 200 });
    }, 100);
  }, []);

  const formattedDate = new Date(dashboard.publishedAt || dashboard.updatedAt).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });

  // Handle PDF export
  const handleExportPDF = useCallback(async () => {
    if (isExporting) return;
    setIsExporting(true);
    
    try {
      await exportDashboardToPDF('.viewer-canvas', {
        title: dashboard.name,
        filename: `${dashboard.name.replace(/[^a-z0-9]/gi, '-').toLowerCase()}-roadmap.pdf`,
        includeHeader: true
      });
    } finally {
      setIsExporting(false);
    }
  }, [dashboard.name, isExporting]);

  // Handle JSON export
  const handleExportJSON = useCallback(() => {
    const data = {
      name: dashboard.name,
      description: dashboard.description,
      nodes: dashboard.nodes,
      edges: dashboard.edges,
      exportedAt: new Date().toISOString(),
      version: dashboard.version
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${dashboard.name.replace(/[^a-z0-9]/gi, '-').toLowerCase()}-dashboard.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [dashboard]);

  return (
    <div className="dashboard-viewer">
      {/* Navigation */}
      <nav className="viewer-nav">
        <div className="nav-brand">
          <a href="/">
            <img src="/HFNeon.png" alt="Hackfluency" />
            <span className="logo-text">
              <span className="logo-hack">Hack</span>
              <span className="logo-fluency">fluency</span>
            </span>
          </a>
          <span className="nav-divider" />
          <a href="/dashboards" className="nav-back">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M19 12H5M12 19l-7-7 7-7"/>
            </svg>
            All Dashboards
          </a>
        </div>
        <div className="nav-actions">
          <button 
            className="nav-btn"
            onClick={handleExportJSON}
            title="Export JSON"
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
              <polyline points="7 10 12 15 17 10"/>
              <line x1="12" y1="15" x2="12" y2="3"/>
            </svg>
          </button>
          <button 
            className="nav-btn" 
            onClick={handleExportPDF}
            disabled={isExporting}
            title="Export to PDF"
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
              <polyline points="14 2 14 8 20 8"/>
              <line x1="12" y1="18" x2="12" y2="12"/>
              <line x1="9" y1="15" x2="15" y2="15"/>
            </svg>
          </button>
          <a href="/dashboards" className="nav-btn" title="All Dashboards">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="3" y="3" width="7" height="7" rx="1"/>
              <rect x="14" y="3" width="7" height="7" rx="1"/>
              <rect x="3" y="14" width="7" height="7" rx="1"/>
              <rect x="14" y="14" width="7" height="7" rx="1"/>
            </svg>
          </a>
          <a href="/dashboard-builder" className="nav-btn primary" title="Create New Dashboard">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
            </svg>
            <span>New</span>
          </a>
        </div>
      </nav>

      {/* Header */}
      <header className="viewer-header">
        <div className="viewer-header-content">
          <div className="viewer-meta">
            <span className={`status-badge ${dashboard.status}`}>
              {dashboard.status === 'published' ? 'Published' : dashboard.status}
            </span>
            <span className="viewer-date">Last updated: {formattedDate}</span>
            <span className="viewer-version">v{dashboard.version}</span>
          </div>
          <h1 className="viewer-title">{dashboard.name}</h1>
          {dashboard.description && (
            <p className="viewer-description">{dashboard.description}</p>
          )}
        </div>
        <DashboardStats nodes={dashboard.nodes} />
      </header>

      {/* Canvas */}
      <div className="viewer-canvas" ref={canvasRef}>
        <QuarterColumnsViewer />
        <div className="react-flow-wrapper">
          <ReactFlow
            nodes={scaledNodes}
            edges={dashboard.edges}
            nodeTypes={nodeTypes}
            onInit={onInit}
            fitView
            fitViewOptions={{ padding: 0.1 }}
            // Disable all interactions for read-only view
            nodesDraggable={false}
            nodesConnectable={false}
            nodesFocusable={false}
            edgesFocusable={false}
            elementsSelectable={false}
            panOnDrag={false}
            zoomOnScroll={false}
            zoomOnPinch={false}
            zoomOnDoubleClick={false}
            panOnScroll={false}
            preventScrolling
            // Zoom limits
            minZoom={0.8}
            maxZoom={1.2}
            // Edge styling
            defaultEdgeOptions={{ style: { stroke: '#00D26A', strokeWidth: 2 } }}
          >
            <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="rgba(255,255,255,0.03)" />
          </ReactFlow>
        </div>
      </div>
    </div>
  );
};

export default DashboardViewer;

