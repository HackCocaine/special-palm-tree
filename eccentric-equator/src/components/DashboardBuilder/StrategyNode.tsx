import React, { memo } from 'react';
import { Handle, Position, NodeResizer } from '@xyflow/react';
import type { NodeProps } from '@xyflow/react';
import type { StrategyNodeData, NodeCategory } from './types';
import { CATEGORY_CONFIG, STATUS_CONFIG, PRIORITY_CONFIG } from './types';

const Icons: Record<string, React.FC<{ size?: number }>> = {
  target: ({ size = 16 }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>
    </svg>
  ),
  zap: ({ size = 16 }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
    </svg>
  ),
  flag: ({ size = 16 }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/>
    </svg>
  ),
  alert: ({ size = 16 }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
    </svg>
  ),
  shield: ({ size = 16 }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  ),
  chart: ({ size = 16 }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M18 20V10M12 20V4M6 20v-6"/>
    </svg>
  ),
};

interface StrategyNodeProps {
  data: StrategyNodeData;
  selected?: boolean;
}

const StrategyNode: React.FC<StrategyNodeProps> = ({ data, selected }) => {
  const config = CATEGORY_CONFIG[data.category];
  const statusConfig = STATUS_CONFIG[data.status];
  const priorityConfig = PRIORITY_CONFIG[data.priority];
  const IconComponent = Icons[config.icon];

  return (
    <div
      className={`strategy-node ${selected ? 'selected' : ''}`}
      style={{ '--node-color': config.color } as React.CSSProperties}
    >
      <NodeResizer
        isVisible={selected}
        minWidth={180}
        maxWidth={500}
        minHeight={120}
        handleStyle={{ width: '8px', height: '8px', backgroundColor: 'white', border: '2px solid #00D26A' }}
        lineStyle={{ borderColor: '#00D26A' }}
      />

      {/* Connection Handles */}
      <Handle type="target" position={Position.Top} className="node-handle" />
      <Handle type="target" position={Position.Left} className="node-handle" />
      <Handle type="source" position={Position.Bottom} className="node-handle" />
      <Handle type="source" position={Position.Right} className="node-handle" />

      {/* Header */}
      <div className="node-header">
        <div className="node-icon" style={{ backgroundColor: `${config.color}20`, color: config.color }}>
          {IconComponent && <IconComponent size={14} />}
        </div>
        <span className="node-category" style={{ color: config.color }}>{config.label}</span>
      </div>

      {/* Title */}
      <div className="node-title">{data.title}</div>

      {/* Metric Value */}
      {data.category === 'metric' && data.value && (
        <div className="node-value" style={{ color: config.color }}>{data.value}</div>
      )}

      {/* Description */}
      {data.description && (
        <div className="node-description">{data.description}</div>
      )}

      {/* Footer - Status & Priority */}
      <div className="node-footer">
        <div className="node-status">
          <span className="status-dot" style={{ backgroundColor: statusConfig.color }} />
          <span>{statusConfig.label}</span>
        </div>
        <span 
          className="node-priority"
          style={{ backgroundColor: `${priorityConfig.color}20`, color: priorityConfig.color }}
        >
          {priorityConfig.label}
        </span>
      </div>
    </div>
  );
};

export default memo(StrategyNode);
