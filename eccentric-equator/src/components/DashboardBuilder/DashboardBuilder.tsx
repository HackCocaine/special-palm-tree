import React, { useCallback, useState, useMemo, useRef, useEffect } from 'react';
import {
  ReactFlow,
  Controls,
  Background,
  MiniMap,
  addEdge,
  useNodesState,
  useEdgesState,
  BackgroundVariant,
  type Connection,
  type Edge,
  type Node,
  type NodeTypes,
  type NodeChange,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import './styles.css';

import StrategyNode from './StrategyNode';
import type { StrategyNodeData, NodeCategory, Quarter, Status, Priority } from './types';
import { CATEGORY_CONFIG, STATUS_CONFIG, PRIORITY_CONFIG, QUARTER_CONFIG } from './types';
import { saveDashboard, publishDashboard, type SavedDashboard } from './dashboardStorage';
import { exportDashboardToPDF } from './pdfExport';

// --- FLEXIBLE LAYOUT REFACTOR ---
// 1. Constants are adjusted for a dynamic layout.
// 2. Positioning helpers are moved inside the component and memoized.
// 3. Initial node positions are now calculated dynamically in a useEffect.
// 4. The QuarterColumns component is simplified.

const QUARTERS: Quarter[] = ['q1', 'q2', 'q3', 'q4'];
const NODE_WIDTH = 200; // Approximate node width
const QUARTER_PADDING = 20; // Padding from quarter edges

// Node data is separated from position, which is now dynamic.
const initialNodeDetails = [
  { id: '1', data: { category: 'objective', quarter: 'q1', title: 'Security Assessment', description: 'Complete baseline security evaluation', status: 'done', priority: 'critical' } },
  { id: '2', data: { category: 'initiative', quarter: 'q1', title: 'Asset Inventory', description: 'Catalog all digital assets', status: 'done', priority: 'high' } },
  { id: '3', data: { category: 'risk', quarter: 'q1', title: 'Legacy Systems', description: 'Outdated systems lacking patches', status: 'active', priority: 'critical' } },
  { id: '4', data: { category: 'initiative', quarter: 'q2', title: 'Zero Trust Architecture', description: 'Implement ZTA framework', status: 'active', priority: 'critical' } },
  { id: '5', data: { category: 'control', quarter: 'q2', title: 'MFA Deployment', description: 'Multi-factor auth for all users', status: 'active', priority: 'high' } },
  { id: '6', data: { category: 'milestone', quarter: 'q2', title: 'SOC 2 Prep', description: 'Prepare audit documentation', status: 'planned', priority: 'high' } },
  { id: '7', data: { category: 'initiative', quarter: 'q3', title: 'SIEM Enhancement', description: 'Upgrade threat detection', status: 'planned', priority: 'high' } },
  { id: '8', data: { category: 'control', quarter: 'q3', title: 'Incident Response', description: 'Automated IR playbooks', status: 'planned', priority: 'medium' } },
  { id: '9', data: { category: 'metric', quarter: 'q3', title: 'MTTD', description: 'Mean time to detect', status: 'planned', priority: 'medium', value: '< 4h' } },
  { id: '10', data: { category: 'objective', quarter: 'q4', title: 'SOC 2 Certification', description: 'Achieve compliance', status: 'planned', priority: 'critical' } },
  { id: '11', data: { category: 'milestone', quarter: 'q4', title: 'Annual Review', description: 'Strategy effectiveness review', status: 'planned', priority: 'high' } },
  { id: '12', data: { category: 'metric', quarter: 'q4', title: 'Security Score', description: 'Overall security rating', status: 'planned', priority: 'high', value: '85%' } },
];

const initialEdges: Edge[] = [
  { id: 'e1-2', source: '1', target: '2', animated: true },
  { id: 'e2-4', source: '2', target: '4', animated: true },
  { id: 'e3-5', source: '3', target: '5', style: { stroke: '#f59e0b' } },
  { id: 'e4-7', source: '4', target: '7', animated: true },
  { id: 'e5-6', source: '5', target: '6' },
  { id: 'e6-10', source: '6', target: '10', animated: true },
  { id: 'e7-8', source: '7', target: '8' },
  { id: 'e8-9', source: '8', target: '9' },
  { id: 'e10-11', source: '10', target: '11' },
  { id: 'e11-12', source: '11', target: '12' },
];

const nodeTypes: NodeTypes = {
  strategy: StrategyNode,
};

// Sidebar palette item component
const PaletteItem: React.FC<{
  category: NodeCategory;
  onDragStart: (event: React.DragEvent, category: NodeCategory) => void;
}> = ({ category, onDragStart }) => {
  const config = CATEGORY_CONFIG[category];
  
  const icons: Record<string, React.ReactElement> = {
    target: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>,
    zap: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>,
    flag: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg>,
    alert: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>,
    shield: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
    chart: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 20V10M12 20V4M6 20v-6"/></svg>,
  };

  return (
    <div
      className="palette-item"
      style={{ '--item-color': config.color, '--item-bg': `${config.color}20` } as React.CSSProperties}
      draggable
      onDragStart={(e) => onDragStart(e, category)}
    >
      <div className="palette-icon">{icons[config.icon]}</div>
      <span className="palette-label">{config.label}</span>
    </div>
  );
};

// Quarter column overlay - now fully flexible, with no inline styles.
const QuarterColumns: React.FC = () => (
  <div className="quarter-columns">
    {(['q1', 'q2', 'q3', 'q4'] as Quarter[]).map((q) => (
      <div 
        key={q} 
        className="quarter-column"
      >
        <div className="quarter-label">
          <span className={`quarter-badge ${q}`}>{QUARTER_CONFIG[q].label}</span>
          <span className="quarter-name">{QUARTER_CONFIG[q].months}</span>
        </div>
      </div>
    ))}
  </div>
);

// Properties Panel
const PropertiesPanel: React.FC<{
  selectedNode: Node<StrategyNodeData> | null;
  onUpdate: (data: Partial<StrategyNodeData>) => void;
  onDelete: () => void;
}> = ({ selectedNode, onUpdate, onDelete }) => {
  if (!selectedNode) {
    return (
      <div className="builder-panel">
        <div className="panel-empty">
          <div className="panel-empty-icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <rect x="3" y="3" width="7" height="7" rx="1"/>
              <rect x="14" y="3" width="7" height="7" rx="1"/>
              <rect x="3" y="14" width="7" height="7" rx="1"/>
              <rect x="14" y="14" width="7" height="7" rx="1"/>
            </svg>
          </div>
          <p>Select a node</p>
          <small>Click on a node to edit properties</small>
        </div>
      </div>
    );
  }

  const data = selectedNode.data;
  const config = CATEGORY_CONFIG[data.category];

  return (
    <div className="builder-panel">
      <div className="panel-header">
        <span className="panel-type" style={{ background: `${config.color}20`, color: config.color }}>
          {config.label}
        </span>
        <button className="panel-delete" onClick={onDelete} title="Delete node">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
          </svg>
        </button>
      </div>

      <div className="form-group">
        <label>Title</label>
        <input
          type="text"
          value={data.title}
          onChange={(e) => onUpdate({ title: e.target.value })}
        />
      </div>

      <div className="form-group">
        <label>Description</label>
        <textarea
          value={data.description}
          onChange={(e) => onUpdate({ description: e.target.value })}
          rows={2}
        />
      </div>

      {data.category === 'metric' && (
        <div className="form-group">
          <label>Value</label>
          <input
            type="text"
            value={data.value || ''}
            onChange={(e) => onUpdate({ value: e.target.value })}
            placeholder="e.g., 85%"
          />
        </div>
      )}

      <div className="form-row">
        <div className="form-group">
          <label>Status</label>
          <select
            value={data.status}
            onChange={(e) => onUpdate({ status: e.target.value as Status })}
          >
            {Object.entries(STATUS_CONFIG).map(([key, val]) => (
              <option key={key} value={key}>{val.label}</option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label>Priority</label>
          <select
            value={data.priority}
            onChange={(e) => onUpdate({ priority: e.target.value as Priority })}
          >
            {Object.entries(PRIORITY_CONFIG).map(([key, val]) => (
              <option key={key} value={key}>{val.label}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="form-group">
        <label>Quarter</label>
        <select
          value={data.quarter}
          onChange={(e) => onUpdate({ quarter: e.target.value as Quarter })}
        >
          {Object.entries(QUARTER_CONFIG).map(([key, val]) => (
            <option key={key} value={key}>{val.label} - {val.months}</option>
          ))}
        </select>
      </div>
    </div>
  );
};

// Publish Modal Component
const PublishModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  onPublish: (name: string, description: string, publishImmediately: boolean) => void;
}> = ({ isOpen, onClose, onPublish }) => {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [publishImmediately, setPublishImmediately] = useState(true);

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    onPublish(name.trim(), description.trim(), publishImmediately);
    setName('');
    setDescription('');
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M4 12v8a2 2 0 002 2h12a2 2 0 002-2v-8"/>
              <polyline points="16 6 12 2 8 6"/>
              <line x1="12" y1="2" x2="12" y2="15"/>
            </svg>
            Save & Publish Dashboard
          </h2>
          <button className="modal-close" onClick={onClose}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="modal-body">
            <div className="form-group">
              <label>Dashboard Name *</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g., Q1-Q4 2026 Security Roadmap"
                autoFocus
                required
              />
            </div>
            <div className="form-group">
              <label>Description</label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Brief description of this dashboard's purpose..."
                rows={3}
              />
            </div>
            <div className="form-group checkbox-group">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={publishImmediately}
                  onChange={(e) => setPublishImmediately(e.target.checked)}
                />
                <span className="checkmark" />
                <span>Publish immediately (make visible at unique URL)</span>
              </label>
            </div>
          </div>
          <div className="modal-footer">
            <button type="button" className="btn-secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn-primary" disabled={!name.trim()}>
              {publishImmediately ? 'Save & Publish' : 'Save as Draft'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

// Success Toast Component
const SuccessToast: React.FC<{
  dashboard: SavedDashboard | null;
  onClose: () => void;
}> = ({ dashboard, onClose }) => {
  if (!dashboard) return null;

  const viewUrl = `/dashboards/${dashboard.id}`;
  
  return (
    <div className="toast-container">
      <div className="toast success">
        <div className="toast-icon">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
            <polyline points="22 4 12 14.01 9 11.01"/>
          </svg>
        </div>
        <div className="toast-content">
          <strong>Dashboard {dashboard.status === 'published' ? 'Published' : 'Saved'}!</strong>
          <p>{dashboard.name}</p>
          {dashboard.status === 'published' && (
            <a href={viewUrl} className="toast-link">
              View Dashboard →
            </a>
          )}
        </div>
        <button className="toast-close" onClick={onClose}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
        </button>
      </div>
    </div>
  );
};

// Main Dashboard Builder Component
const DashboardBuilder: React.FC = () => {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [showPublishModal, setShowPublishModal] = useState(false);
  const [publishedDashboard, setPublishedDashboard] = useState<SavedDashboard | null>(null);
  const [isExportingPDF, setIsExportingPDF] = useState(false);
  const canvasRef = useRef<HTMLDivElement>(null);
  const [canvasWidth, setCanvasWidth] = useState(0);

  // --- DYNAMIC LAYOUT LOGIC ---

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
    // Set initial width
    setCanvasWidth(canvasElement.offsetWidth);

    return () => observer.disconnect();
  }, []);

  // 2. Memoize positioning functions based on canvas width
  const quarterWidth = canvasWidth / 4;

  const getQuarterBounds = useCallback((quarter: Quarter, nodeWidth: number = NODE_WIDTH) => {
    const quarterIndex = QUARTERS.indexOf(quarter);
    const minX = quarterIndex * quarterWidth + QUARTER_PADDING;
    const maxX = (quarterIndex + 1) * quarterWidth - nodeWidth - QUARTER_PADDING;
    return { minX, maxX, quarterIndex };
  }, [quarterWidth]);

  const getQuarterFromPosition = useCallback((x: number): Quarter => {
    const centerX = x + NODE_WIDTH / 2;
    const quarterIndex = Math.min(3, Math.max(0, Math.floor(centerX / quarterWidth)));
    return QUARTERS[quarterIndex];
  }, [quarterWidth]);

  const constrainToQuarter = useCallback((x: number, quarter: Quarter, nodeWidth?: number): number => {
    const { minX, maxX } = getQuarterBounds(quarter, nodeWidth);
    return Math.min(maxX, Math.max(minX, x));
  }, [getQuarterBounds]);

  const getQuarterCenterX = useCallback((quarter: Quarter, nodeWidth?: number): number => {
    const { minX, maxX } = getQuarterBounds(quarter, nodeWidth);
    return minX + (maxX - minX) / 2;
  }, [getQuarterBounds]);


  // 3. Dynamically position initial nodes once canvas is measured
  useEffect(() => {
    if (canvasWidth > 0 && nodes.length === 0) {
      const yOffsets: Record<Quarter, number> = { q1: 0, q2: 0, q3: 0, q4: 0 };
      const Y_SPACING = 160;

      const positionedNodes = initialNodeDetails.map(detail => {
        const quarter = detail.data.quarter;
        const yPos = 80 + yOffsets[quarter];
        yOffsets[quarter] += Y_SPACING;

        return {
          id: detail.id,
          type: 'strategy',
          position: {
            x: getQuarterCenterX(quarter),
            y: yPos,
          },
          data: detail.data,
        };
      });
      setNodes(positionedNodes);
    }
  }, [canvasWidth, getQuarterCenterX, nodes.length, setNodes]);
  
  // Custom onNodesChange that enforces quarter boundaries
  const onNodesChangeCustom = useCallback(
    (changes: NodeChange[]) => {
      const constrainedChanges = changes.map((change) => {
        if (change.type === 'position' && change.position && change.dragging) {
          const node = nodes.find((n) => n.id === change.id);
          if (node) {
            const { quarter } = node.data as StrategyNodeData;
            change.position.x = constrainToQuarter(change.position.x, quarter, node.width);
            change.position.y = Math.max(50, change.position.y);
          }
        }
        return change;
      });

      onNodesChange(constrainedChanges);
    },
    [nodes, constrainToQuarter, onNodesChange]
  );

  const selectedNode = useMemo(
    () => nodes.find((n) => n.id === selectedNodeId) || null,
    [nodes, selectedNodeId]
  );

  const onConnect = useCallback(
    (connection: Connection) => {
      setEdges((eds) => addEdge({ ...connection, animated: true }, eds));
    },
    [setEdges]
  );

  const onNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    setSelectedNodeId(node.id);
  }, []);

  const onPaneClick = useCallback(() => {
    setSelectedNodeId(null);
  }, []);

  const onDragStart = (event: React.DragEvent, category: NodeCategory) => {
    event.dataTransfer.setData('application/reactflow-category', category);
    event.dataTransfer.effectAllowed = 'move';
  };

  const onDragOver = useCallback((event: React.DragEvent) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
  }, []);

  const onDrop = useCallback(
    (event: React.DragEvent) => {
      event.preventDefault();

      const category = event.dataTransfer.getData('application/reactflow-category') as NodeCategory;
      if (!category) return;

      const reactFlowBounds = canvasRef.current?.getBoundingClientRect();
      if (!reactFlowBounds) return;

      let positionX = event.clientX - reactFlowBounds.left;
      const positionY = Math.max(80, event.clientY - reactFlowBounds.top - 50);

      const quarter = getQuarterFromPosition(positionX);
      positionX = constrainToQuarter(positionX, quarter);

      const config = CATEGORY_CONFIG[category];
      const newNode: Node<StrategyNodeData> = {
        id: `node-${Date.now()}`,
        type: 'strategy',
        position: { x: positionX, y: positionY },
        data: {
          category,
          quarter,
          title: `New ${config.label}`,
          description: 'Click to edit description',
          status: 'planned',
          priority: 'medium',
          value: category === 'metric' ? '0%' : undefined,
        },
      };

      setNodes((nds) => [...nds, newNode]);
      setSelectedNodeId(newNode.id);
    },
    [setNodes, getQuarterFromPosition, constrainToQuarter]
  );

  const updateSelectedNode = useCallback(
    (updates: Partial<StrategyNodeData>) => {
      if (!selectedNodeId) return;

      setNodes((nds) =>
        nds.map((node) => {
          if (node.id === selectedNodeId) {
            const updatedNode = { ...node, data: { ...node.data, ...updates } };

            if (updates.quarter && updates.quarter !== node.data.quarter) {
              updatedNode.position.x = getQuarterCenterX(updates.quarter, node.width);
            }
            
            return updatedNode;
          }
          return node;
        })
      );
    },
    [selectedNodeId, setNodes, getQuarterCenterX]
  );

  const deleteSelectedNode = useCallback(() => {
    if (!selectedNodeId) return;
    setNodes((nds) => nds.filter((n) => n.id !== selectedNodeId));
    setEdges((eds) => eds.filter((e) => e.source !== selectedNodeId && e.target !== selectedNodeId));
    setSelectedNodeId(null);
  }, [selectedNodeId, setNodes, setEdges]);

  const clearAll = useCallback(() => {
    if (confirm('Clear all nodes and connections?')) {
      setNodes([]);
      setEdges([]);
      setSelectedNodeId(null);
    }
  }, [setNodes, setEdges]);

  const exportData = useCallback(() => {
    const data = { nodes, edges };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'strategy-dashboard.json';
    a.click();
    URL.revokeObjectURL(url);
  }, [nodes, edges]);

  const exportPDF = useCallback(async () => {
    if (isExportingPDF) return;
    setIsExportingPDF(true);
    
    try {
      await exportDashboardToPDF('.builder-canvas', {
        title: 'Strategy Dashboard',
        filename: 'strategy-roadmap.pdf',
        includeHeader: true
      });
    } finally {
      setIsExportingPDF(false);
    }
  }, [isExportingPDF]);

  const handlePublish = useCallback((name: string, description: string, publishImmediately: boolean) => {
    const saved = saveDashboard(name, description, nodes, edges);
    
    if (publishImmediately) {
      const published = publishDashboard(saved.id);
      setPublishedDashboard(published);
    } else {
      setPublishedDashboard(saved);
    }
    
    setShowPublishModal(false);
    
    setTimeout(() => setPublishedDashboard(null), 5000);
  }, [nodes, edges]);

  return (
    <div className="dashboard-builder">
      {/* Navigation */}
      <nav className="builder-nav">
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
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            Strategy Dashboard
          </span>
        </div>
        <div className="nav-actions">
          <button className="nav-btn" onClick={clearAll} title="Clear all">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
            </svg>
          </button>
          <button className="nav-btn" onClick={exportData} title="Export JSON">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
            </svg>
          </button>
          <button className="nav-btn" onClick={exportPDF} disabled={isExportingPDF} title="Export PDF">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
              <polyline points="14 2 14 8 20 8"/>
              <line x1="12" y1="18" x2="12" y2="12"/>
              <line x1="9" y1="15" x2="15" y2="15"/>
            </svg>
          </button>
          <a href="/dashboards" className="nav-btn" title="View All Dashboards">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="3" y="3" width="7" height="7" rx="1"/>
              <rect x="14" y="3" width="7" height="7" rx="1"/>
              <rect x="3" y="14" width="7" height="7" rx="1"/>
              <rect x="14" y="14" width="7" height="7" rx="1"/>
            </svg>
          </a>
          <button className="nav-btn publish" onClick={() => setShowPublishModal(true)} title="Save & Publish">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M4 12v8a2 2 0 002 2h12a2 2 0 002-2v-8"/>
              <polyline points="16 6 12 2 8 6"/>
              <line x1="12" y1="2" x2="12" y2="15"/>
            </svg>
            <span>Publish</span>
          </button>
        </div>
      </nav>

      <PublishModal
        isOpen={showPublishModal}
        onClose={() => setShowPublishModal(false)}
        onPublish={handlePublish}
      />

      <SuccessToast
        dashboard={publishedDashboard}
        onClose={() => setPublishedDashboard(null)}
      />

      <div className="builder-content">
        <aside className="builder-sidebar">
          <div className="sidebar-section">
            <div className="sidebar-title">Elements</div>
            <div className="element-palette">
              {(Object.keys(CATEGORY_CONFIG) as NodeCategory[]).map((cat) => (
                <PaletteItem key={cat} category={cat} onDragStart={onDragStart} />
              ))}
            </div>
          </div>
          <div className="sidebar-section">
            <div className="sidebar-title">Tips</div>
            <div style={{ fontSize: '0.75rem', color: '#6a6a6a', lineHeight: 1.6 }}>
              <p>• Drag elements to canvas</p>
              <p>• Nodes stay in their quarter</p>
              <p>• Change quarter in properties</p>
              <p>• Drag handles to connect</p>
              <p>• Delete key removes node</p>
            </div>
          </div>
        </aside>

        <div className="builder-canvas" ref={canvasRef} onDragOver={onDragOver} onDrop={onDrop}>
          <QuarterColumns />
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChangeCustom}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onNodeClick={onNodeClick}
            onPaneClick={onPaneClick}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.1, minZoom: 0.9, maxZoom: 1.3 }}
            snapToGrid
            snapGrid={[10, 10]}
            minZoom={0.9}
            maxZoom={1.3}
            panOnDrag={false}
            zoomOnScroll={false}
            zoomOnPinch={false}
            zoomOnDoubleClick={false}
            autoPanOnNodeDrag={false}
            defaultEdgeOptions={{ animated: true, style: { stroke: '#00D26A', strokeWidth: 2 } }}
          >
            <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="rgba(255,255,255,0.03)" />
            <MiniMap
              nodeColor={(n) => CATEGORY_CONFIG[(n.data as StrategyNodeData).category]?.color || '#00D26A'}
              maskColor="rgba(0, 210, 106, 0.1)"
            />
          </ReactFlow>
        </div>

        <PropertiesPanel
          selectedNode={selectedNode as Node<StrategyNodeData> | null}
          onUpdate={updateSelectedNode}
          onDelete={deleteSelectedNode}
        />
      </div>
    </div>
  );
};

export default DashboardBuilder;
