import React, { useMemo, useCallback, useState, useRef, useEffect } from 'react';
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
  type Viewport,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import './viewer-styles.css';

import StrategyNode from './StrategyNode';
import StrategyEdge from './StrategyEdge';
import type { StrategyNodeData, Quarter } from './types';
import { QUARTER_CONFIG } from './types';
import type { SavedDashboard } from './dashboardStorage';
import { exportDashboardToPDF } from './pdfExport';
import { useDeviceDetection, useReactFlowConfig, type DeviceType, BREAKPOINTS } from './useDeviceDetection';

// --- FIXED COORDINATE SYSTEM ---
const VIRTUAL_WIDTH = 1440;
const QUARTERS: Quarter[] = ['q1', 'q2', 'q3', 'q4'];

const nodeTypes: NodeTypes = {
  strategy: StrategyNode,
};

const edgeTypes: EdgeTypes = {
  strategy: StrategyEdge as EdgeTypes['strategy'],
};

interface DashboardViewerProps {
  dashboard: SavedDashboard;
  publicMode?: boolean;
}

// Store viewport preference in localStorage
const VIEWPORT_STORAGE_KEY = 'dashboard-viewport-zoom';

function getStoredViewport(): Viewport | null {
  if (typeof window === 'undefined') return null;
  const stored = localStorage.getItem(VIEWPORT_STORAGE_KEY);
  if (stored) {
    try {
      return JSON.parse(stored);
    } catch {
      return null;
    }
  }
  return null;
}

function storeViewport(viewport: Viewport) {
  if (typeof window !== 'undefined') {
    localStorage.setItem(VIEWPORT_STORAGE_KEY, JSON.stringify(viewport));
  }
}

function clearViewportStorage() {
  if (typeof window !== 'undefined') {
    localStorage.removeItem(VIEWPORT_STORAGE_KEY);
  }
}

// Background guides that move and scale with the flow
function StrategicBackground() {
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
}

interface DashboardStatsProps {
  nodes: Node<StrategyNodeData>[];
}

function DashboardStats({ nodes }: DashboardStatsProps) {
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

function DashboardViewer({ dashboard, publicMode = false }: DashboardViewerProps) {
  const [isExporting, setIsExporting] = useState(false);
  const [viewport, setViewport] = useState<Viewport | null>(null);
  const [resetViewportKey, setResetViewportKey] = useState(0);
  const canvasRef = useRef<HTMLDivElement>(null);
  const deviceInfo = useDeviceDetection();
  const getReactFlowConfig = useReactFlowConfig(deviceInfo);
  const previousDeviceType = useRef<DeviceType | null>(null);
  
  // Get configuration based on device type
  const config = getReactFlowConfig();
  
  // Handle device type transitions - reset viewport when switching to desktop
  useEffect(() => {
    if (previousDeviceType.current && previousDeviceType.current !== deviceInfo.type) {
      // Device type changed
      const wasMobileOrTablet = previousDeviceType.current !== 'desktop';
      const isNowDesktop = deviceInfo.type === 'desktop';
      
      if (wasMobileOrTablet && isNowDesktop) {
        // Transitioning from mobile/tablet to desktop - reset to default viewport
        clearViewportStorage();
        setResetViewportKey(prev => prev + 1);
      }
    }
    
    previousDeviceType.current = deviceInfo.type;
  }, [deviceInfo.type]);

  // Handle viewport changes (only on mobile/tablet where zoom is enabled)
  const onViewportChange = useCallback((newViewport: Viewport) => {
    setViewport(newViewport);
    if (deviceInfo.type !== 'desktop') {
      storeViewport(newViewport);
    }
  }, [deviceInfo.type]);

  const handleExportPDF = useCallback(async () => {
    if (isExporting) return;
    
    // Reset viewport to default desktop position before export
    clearViewportStorage();
    setResetViewportKey(prev => prev + 1);
    
    // Wait for ReactFlow to reset to default viewport
    await new Promise(resolve => setTimeout(resolve, 150));
    
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

  // Determine if controls should be shown based on device type
  const showZoomControls = deviceInfo.type !== 'desktop';

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
        <div 
          key={resetViewportKey} 
          className={`react-flow-wrapper device-${deviceInfo.type}`}
        >
          <ReactFlow
            key={`${deviceInfo.type}-${resetViewportKey}`}
            nodes={dashboard.nodes}
            edges={dashboard.edges || []}
            nodeTypes={nodeTypes}
            nodeOrigin={[0.5, 0]}
            defaultViewport={config.defaultViewport}
            onViewportChange={onViewportChange}
            fitView={!publicMode}
            fitViewOptions={config.fitViewOptions}
            nodesDraggable={false}
            nodesConnectable={false}
            nodesFocusable={false}
            edgesFocusable={false}
            elementsSelectable={false}
            panOnDrag={config.panOnDrag}
            translateExtent={config.translateExtent}
            zoomOnScroll={config.zoomOnScroll}
            zoomOnPinch={config.zoomOnPinch}
            zoomOnDoubleClick={config.zoomOnDoubleClick}
            minZoom={config.minZoom}
            maxZoom={config.maxZoom}
            edgeTypes={edgeTypes}
          >
            <StrategicBackground />
            <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="rgba(255,255,255,0.03)" />
            {showZoomControls && (
              <MiniMap
                nodeStrokeColor={(node) => {
                  const data = node.data as StrategyNodeData;
                  if (!data) return '#fff';
                  switch (data.status) {
                    case 'done': return '#00D26A';
                    case 'active': return '#3b82f6';
                    case 'blocked': return '#ef4444';
                    default: return '#8b5cf6';
                  }
                }}
                nodeColor={(node) => {
                  const data = node.data as StrategyNodeData;
                  if (!data) return '#1a1a1a';
                  switch (data.status) {
                    case 'done': return 'rgba(0, 210, 106, 0.3)';
                    case 'active': return 'rgba(59, 130, 246, 0.3)';
                    case 'blocked': return 'rgba(239, 68, 68, 0.3)';
                    default: return 'rgba(139, 92, 246, 0.3)';
                  }
                }}
                maskColor="rgba(0, 0, 0, 0.5)"
                style={{
                  background: '#111111',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  borderRadius: '8px',
                }}
              />
            )}
          </ReactFlow>
        </div>
      </div>
    </div>
  );
}

// Wrap with provider
function DashboardViewerWrapper(props: DashboardViewerProps) {
  return (
    <ReactFlowProvider>
      <DashboardViewer {...props} />
    </ReactFlowProvider>
  );
}

export default DashboardViewerWrapper;
