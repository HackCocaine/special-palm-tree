import React, { useMemo, useCallback, useState, useRef } from 'react';
import {
  ReactFlow,
  MiniMap,
  Background,
  BackgroundVariant,
  useViewport,
  ReactFlowProvider,
  type Node,
  type NodeTypes,
  type ReactFlowInstance,
  type EdgeTypes,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import './viewer-styles.css';

import StrategyNode from './StrategyNode';
import StrategyEdge from './StrategyEdge';
import type { StrategyNodeData, Quarter } from './types';
import { QUARTER_CONFIG } from './types';
import type { SavedDashboard } from './dashboardStorage';
import { exportDashboardToPDF } from './pdfExport';

// --- FIXED COORDINATE SYSTEM ---
const VIRTUAL_WIDTH = 1440;
const QUARTERS: Quarter[] = ['q1', 'q2', 'q3', 'q4'];

const nodeTypes: NodeTypes = {
  strategy: StrategyNode,
};

const edgeTypes: EdgeTypes = {
  strategy: StrategyEdge,
};

interface DashboardViewerProps {
  dashboard: SavedDashboard;
  publicMode?: boolean;
}

// Background guides that move and scale with the flow
const StrategicBackground: React.FC = () => {
  const { x, y, zoom } = useViewport();
  
  const style: React.CSSProperties = {
    transform: `translate(${x}px, ${y}px) scale(${zoom})`,
    transformOrigin: '0 0',
  };

  return (
    <div className="strategic-bg-guide" style={style}>
      {QUARTERS.map((q) => (
        <div key={q} className="strategic-bg-column">
          <div className="strategic-bg-label">
            <span className="strategic-bg-badge">{QUARTER_CONFIG[q].label}</span>
            <span className="strategic-bg-months">{QUARTER_CONFIG[q].months}</span>
          </div>
        </div>
      ))}
    </div>
  );
};

const DashboardStats: React.FC<{ nodes: Node<StrategyNodeData>[] }> = ({ nodes }) => {
  const stats = useMemo(() => {
    const byStatus: Record<string, number> = { done: 0, active: 0, planned: 0, blocked: 0 };
    nodes.forEach((node) => {
      const data = node.data as StrategyNodeData;
      if (data) byStatus[data.status] = (byStatus[data.status] || 0) + 1;
    });
    return { byStatus, total: nodes.length };
  }, [nodes]);

  const progressPercent = stats.total > 0 ? Math.round((stats.byStatus.done / stats.total) * 100) : 0;

  return (
    <div className="viewer-compact-stats">
      <div className="compact-stat">
        <span className="label">Total:</span> <span className="value">{stats.total}</span>
      </div>
      <div className="compact-stat">
        <span className="label">Done:</span> <span className="value">{progressPercent}%</span>
      </div>
    </div>
  );
};

const DashboardViewer: React.FC<DashboardViewerProps> = ({ dashboard, publicMode = false }) => {
  const [isExporting, setIsExporting] = useState(false);
  const canvasRef = useRef<HTMLDivElement>(null);

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

  return (
    <div className={`dashboard-viewer ${publicMode ? 'public-mode' : ''}`}>
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
          <div className="nav-title">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            {publicMode ? 'Strategy Roadmap Sample' : dashboard.name}
          </div>
        </div>
        
        <div className="nav-actions">
          <DashboardStats nodes={dashboard.nodes || []} />
          <span className="nav-divider" />
          <button className="nav-btn" onClick={handleExportPDF} disabled={isExporting} title="Export PDF">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
              <polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/>
            </svg>
          </button>
          {!publicMode && (
            <a href="/dashboards" className="nav-btn" title="Exit to Dashboards">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M18 6L6 18M6 6l12 12"/>
              </svg>
            </a>
          )}
        </div>
      </nav>

      <div className="viewer-canvas" ref={canvasRef}>
        <div className="react-flow-wrapper">
          <ReactFlow
            nodes={dashboard.nodes}
            edges={dashboard.edges || []}
            nodeTypes={nodeTypes}
            nodeOrigin={[0.5, 0]}
            defaultViewport={{ x: -15, y: -15, zoom: 1.38 }}
            fitView={!publicMode} // Only auto-fit for private dashboards
            fitViewOptions={{ padding: 0.15, maxZoom: 1.0 }}
            nodesDraggable={false}
            nodesConnectable={false}
            nodesFocusable={false}
            edgesFocusable={false}
            elementsSelectable={false}
            panOnDrag={true}
            translateExtent={[[-50, -50], [1490, 1000]]} // Extremely tight pan limits
            zoomOnScroll={false}
            zoomOnPinch={false}
            zoomOnDoubleClick={false}
            minZoom={1.38}
            maxZoom={1.38}
            edgeTypes={edgeTypes}
          >
            <StrategicBackground />
            <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="rgba(255,255,255,0.03)" />
          </ReactFlow>
        </div>
      </div>
    </div>
  );
};

// Wrap with provider
const DashboardViewerWrapper: React.FC<DashboardViewerProps> = (props) => (
  <ReactFlowProvider>
    <DashboardViewer {...props} />
  </ReactFlowProvider>
);

export default DashboardViewerWrapper;
