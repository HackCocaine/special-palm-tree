import React, { useMemo } from 'react';
import {
  ReactFlow,
  Background,
  BackgroundVariant,
  useViewport,
  type Node,
  type NodeTypes,
  type EdgeTypes,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import './viewer-styles.css';

import StrategyNode from './StrategyNode';
import StrategyEdge from './StrategyEdge';
import type { StrategyNodeData, Quarter } from './types';
import { QUARTER_CONFIG } from './types';
import type { SavedDashboard } from './dashboardStorage';

// Desktop configuration for PDF export - always uses desktop settings
const DESKTOP_CONFIG = {
  panOnDrag: false,
  zoomOnScroll: false,
  zoomOnPinch: false,
  zoomOnDoubleClick: false,
  minZoom: 1.38,
  maxZoom: 1.38,
  defaultViewport: { x: -15, y: -15, zoom: 1.38 },
  fitView: true,
  fitViewOptions: { padding: 0.15, maxZoom: 1.0 },
  translateExtent: [[0, 0], [1490, 1000]] as [[number, number], [number, number]],
};

const nodeTypes: NodeTypes = {
  strategy: StrategyNode,
};

const edgeTypes: EdgeTypes = {
  strategy: StrategyEdge as EdgeTypes['strategy'],
};

interface PDFExportContainerProps {
  dashboard: SavedDashboard;
  isExporting: boolean;
  onExportComplete: () => void;
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
      {(['q1', 'q2', 'q3', 'q4'] as Quarter[]).map((q) => (
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

export function PDFExportContainer({ dashboard, isExporting, onExportComplete }: PDFExportContainerProps) {
  // Only render when actually exporting
  if (!isExporting) {
    return null;
  }

  return (
    <div 
      id="pdf-export-container"
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '1920px', // Standard desktop width for high-quality capture
        height: '1080px',
        background: '#0a0a0a',
        zIndex: -1,
        visibility: 'hidden',
        pointerEvents: 'none',
      }}
    >
      <div 
        className="react-flow-wrapper"
        style={{
          position: 'absolute',
          top: 0,
          left: 0,
          width: '100%',
          height: '100%',
        }}
      >
        <ReactFlow
          nodes={dashboard.nodes}
          edges={dashboard.edges || []}
          nodeTypes={nodeTypes}
          nodeOrigin={[0.5, 0]}
          defaultViewport={DESKTOP_CONFIG.defaultViewport}
          fitView={DESKTOP_CONFIG.fitView}
          fitViewOptions={DESKTOP_CONFIG.fitViewOptions}
          nodesDraggable={false}
          nodesConnectable={false}
          nodesFocusable={false}
          edgesFocusable={false}
          elementsSelectable={false}
          panOnDrag={DESKTOP_CONFIG.panOnDrag}
          translateExtent={DESKTOP_CONFIG.translateExtent}
          zoomOnScroll={DESKTOP_CONFIG.zoomOnScroll}
          zoomOnPinch={DESKTOP_CONFIG.zoomOnPinch}
          zoomOnDoubleClick={DESKTOP_CONFIG.zoomOnDoubleClick}
          minZoom={DESKTOP_CONFIG.minZoom}
          maxZoom={DESKTOP_CONFIG.maxZoom}
          edgeTypes={edgeTypes}
          onInit={(instance) => {
            // After initial render, trigger fitView to ensure everything is visible
            setTimeout(() => {
              instance.fitView(DESKTOP_CONFIG.fitViewOptions);
            }, 100);
          }}
        >
          <StrategicBackground />
          <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="rgba(255,255,255,0.03)" />
        </ReactFlow>
      </div>
    </div>
  );
}
