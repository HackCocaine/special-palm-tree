export type NodeCategory = 'objective' | 'initiative' | 'milestone' | 'risk' | 'control' | 'metric';

export type Quarter = 'q1' | 'q2' | 'q3' | 'q4';

export type Status = 'planned' | 'active' | 'done' | 'blocked';

export type Priority = 'low' | 'medium' | 'high' | 'critical';

export interface StrategyNodeData extends Record<string, unknown> {
  category: NodeCategory;
  quarter: Quarter;
  title: string;
  description: string;
  status: Status;
  priority: Priority;
  value?: string; // For metrics
  [key: string]: unknown;
}

export const QUARTER_CONFIG: Record<Quarter, { label: string; color: string; months: string }> = {
  q1: { label: 'Q1', color: '#00D26A', months: 'Jan - Mar' },
  q2: { label: 'Q2', color: '#3b82f6', months: 'Apr - Jun' },
  q3: { label: 'Q3', color: '#8b5cf6', months: 'Jul - Sep' },
  q4: { label: 'Q4', color: '#f59e0b', months: 'Oct - Dec' },
};

export const CATEGORY_CONFIG: Record<NodeCategory, { label: string; color: string; icon: string }> = {
  objective: { label: 'Objective', color: '#00D26A', icon: 'target' },
  initiative: { label: 'Initiative', color: '#3b82f6', icon: 'zap' },
  milestone: { label: 'Milestone', color: '#8b5cf6', icon: 'flag' },
  risk: { label: 'Risk', color: '#ef4444', icon: 'alert' },
  control: { label: 'Control', color: '#14b8a6', icon: 'shield' },
  metric: { label: 'Metric', color: '#f59e0b', icon: 'chart' },
};

export const STATUS_CONFIG: Record<Status, { label: string; color: string }> = {
  planned: { label: 'Planned', color: '#6a6a6a' },
  active: { label: 'Active', color: '#3b82f6' },
  done: { label: 'Done', color: '#00D26A' },
  blocked: { label: 'Blocked', color: '#ef4444' },
};

export const PRIORITY_CONFIG: Record<Priority, { label: string; color: string }> = {
  low: { label: 'Low', color: '#6a6a6a' },
  medium: { label: 'Medium', color: '#3b82f6' },
  high: { label: 'High', color: '#f59e0b' },
  critical: { label: 'Critical', color: '#ef4444' },
};

// Edge Types and Configuration
export type EdgeType = 'dependency' | 'supports' | 'implements' | 'mitigates' | 'mitigated-by' | 'measures';

export type AnimationType = 'flow' | 'pulse' | 'blink' | 'steady';

export interface EdgeTypeConfig {
  label: string;
  color: string;
  description: string;
  dashArray: string;
  animationDuration: string;
  animationType: AnimationType;
  selectedGlow: boolean;
}

export const EDGE_TYPE_CONFIG: Record<EdgeType, EdgeTypeConfig> = {
  dependency: {
    label: 'Dependency',
    color: '#00D26A',
    description: 'Critical security dependency - blocks downstream work',
    dashArray: 'none',
    animationDuration: '2s',
    animationType: 'pulse',
    selectedGlow: true,
  },
  supports: {
    label: 'Supports',
    color: '#3b82f6',
    description: 'Security initiative provides foundational support',
    dashArray: '8 4',
    animationDuration: '1s',
    animationType: 'flow',
    selectedGlow: true,
  },
  implements: {
    label: 'Implements',
    color: '#8b5cf6',
    description: 'Milestone implements security objective',
    dashArray: '2 4',
    animationDuration: '3s',
    animationType: 'pulse',
    selectedGlow: true,
  },
  mitigates: {
    label: 'Mitigates',
    color: '#f59e0b',
    description: 'URGENT: Control mitigates critical security risk',
    dashArray: '6 3 2 3',
    animationDuration: '0.8s',
    animationType: 'blink',
    selectedGlow: true,
  },
  'mitigated-by': {
    label: 'Mitigated By',
    color: '#14b8a6',
    description: 'Risk is covered by implemented control',
    dashArray: '12 6',
    animationDuration: '2.5s',
    animationType: 'steady',
    selectedGlow: true,
  },
  measures: {
    label: 'Measures',
    color: '#eab308',
    description: 'Security metric tracks KPI performance',
    dashArray: '4 4',
    animationDuration: '0.6s',
    animationType: 'flow',
    selectedGlow: true,
  },
};

// Default edge type based on source node category
export const CATEGORY_EDGE_DEFAULTS: Record<NodeCategory, EdgeType> = {
  objective: 'dependency',
  initiative: 'supports',
  milestone: 'implements',
  risk: 'mitigates',
  control: 'mitigated-by',
  metric: 'measures',
};

// Helper function to resolve edge color
export function resolveEdgeColor(
  edgeType: EdgeType | undefined,
  sourceCategory: NodeCategory | undefined
): string {
  // Priority 1: Explicit user selection
  if (edgeType && EDGE_TYPE_CONFIG[edgeType]) {
    return EDGE_TYPE_CONFIG[edgeType].color;
  }

  // Priority 2: Inherited from source node category
  if (sourceCategory && CATEGORY_EDGE_DEFAULTS[sourceCategory]) {
    const inheritedType = CATEGORY_EDGE_DEFAULTS[sourceCategory];
    return EDGE_TYPE_CONFIG[inheritedType].color;
  }

  // Priority 3: Ultimate fallback
  return '#00D26A';
}

// Helper function to get edge type label
export function getEdgeTypeLabel(
  edgeType: EdgeType | undefined,
  sourceCategory: NodeCategory | undefined
): string {
  if (edgeType && EDGE_TYPE_CONFIG[edgeType]) {
    return EDGE_TYPE_CONFIG[edgeType].label;
  }

  if (sourceCategory && CATEGORY_EDGE_DEFAULTS[sourceCategory]) {
    const inheritedType = CATEGORY_EDGE_DEFAULTS[sourceCategory];
    return `${EDGE_TYPE_CONFIG[inheritedType].label} (from ${CATEGORY_CONFIG[sourceCategory].label})`;
  }

  return 'Dependency (Default)';
}
