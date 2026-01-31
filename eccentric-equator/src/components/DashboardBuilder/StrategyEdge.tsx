import React, { useState, useEffect, useRef } from 'react';
import {
  BaseEdge,
  EdgeLabelRenderer,
  getBezierPath,
  useReactFlow,
  type EdgeProps,
} from '@xyflow/react';
import type { EdgeType, StrategyNodeData, NodeCategory, EdgeTypeConfig } from './types';
import {
  resolveEdgeColor,
  getEdgeTypeLabel,
  EDGE_TYPE_CONFIG,
  CATEGORY_EDGE_DEFAULTS,
} from './types';

interface StrategyEdgeData {
  type?: EdgeType;
}

const StrategyEdge: React.FC<EdgeProps<StrategyEdgeData>> = ({
  id,
  source,
  target,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  selected,
}) => {
  const { getNode } = useReactFlow();
  const [isExportMode, setIsExportMode] = useState(false);
  const observerRef = useRef<MutationObserver | null>(null);

  // Detect export mode by checking for pdf-export-mode class on canvas
  useEffect(() => {
    const checkExportMode = () => {
      // Look for canvas container with export mode class
      const canvas = document.querySelector('.builder-canvas, .viewer-canvas');
      const hasExportMode = canvas?.classList.contains('pdf-export-mode') || false;
      setIsExportMode(hasExportMode);
    };

    // Initial check
    checkExportMode();

    // Set up MutationObserver to watch for class changes
    const canvas = document.querySelector('.builder-canvas, .viewer-canvas');
    if (canvas) {
      observerRef.current = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
          if (mutation.type === 'attributes' && mutation.attributeName === 'class') {
            checkExportMode();
          }
        });
      });

      observerRef.current.observe(canvas, {
        attributes: true,
        attributeFilter: ['class'],
      });
    }

    // Also check periodically as a fallback
    const intervalId = setInterval(checkExportMode, 100);

    return () => {
      observerRef.current?.disconnect();
      clearInterval(intervalId);
    };
  }, []);

  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });

  // Get source node to determine inherited properties
  const sourceNode = getNode(source);
  const sourceCategory = sourceNode?.data?.category as NodeCategory | undefined;

  // Resolve effective edge type
  const effectiveType: EdgeType = data?.type || (sourceCategory ? CATEGORY_EDGE_DEFAULTS[sourceCategory] : 'dependency');

  // Get full configuration for the edge type
  const config: EdgeTypeConfig = EDGE_TYPE_CONFIG[effectiveType];

  // Resolve edge color based on type or inheritance
  const edgeColor = resolveEdgeColor(data?.type, sourceCategory);
  const edgeTypeLabel = getEdgeTypeLabel(data?.type, sourceCategory);
  const isExplicit = !!data?.type;

  // Build animation style based on type and export mode
  const getAnimationStyle = (): React.CSSProperties => {
    // Export mode: use static styles without animations
    if (isExportMode) {
      const exportStyle: React.CSSProperties = {
        stroke: edgeColor,
        strokeWidth: selected ? 3 : 2.5, // Slightly thicker for PDF visibility
        strokeOpacity: 1,
        opacity: 1,
        // No animations in export mode
      };

      // Apply dash array for line style variety
      if (config.dashArray !== 'none') {
        exportStyle.strokeDasharray = config.dashArray;
      }

      // Add subtle glow for selected edges in export mode
      if (selected) {
        exportStyle.filter = `drop-shadow(0 0 3px ${edgeColor})`;
      }

      return exportStyle;
    }

    // Normal mode: animated styles
    const baseStyle: React.CSSProperties = {
      stroke: edgeColor,
      strokeWidth: selected ? 3 : 2,
      transition: 'stroke-width 0.15s ease',
      willChange: 'stroke-dashoffset, filter',
    };

    // Apply dash array
    if (config.dashArray !== 'none') {
      baseStyle.strokeDasharray = config.dashArray;
    }

    // Apply animation based on type
    switch (config.animationType) {
      case 'flow':
        baseStyle.animation = `edgeFlow ${config.animationDuration} linear infinite`;
        // Speed up when selected
        if (selected) {
          baseStyle.animation = `edgeFlow ${parseFloat(config.animationDuration) * 0.5}s linear infinite`;
        }
        break;
      case 'pulse':
        baseStyle.animation = `edgePulse ${config.animationDuration} ease-in-out infinite`;
        if (selected) {
          baseStyle.animation = `edgeGlow ${parseFloat(config.animationDuration) * 0.5}s ease-in-out infinite`;
        }
        break;
      case 'blink':
        baseStyle.animation = `edgeBlink ${config.animationDuration} ease-in-out infinite`;
        break;
      case 'steady':
        baseStyle.animation = `edgeFlow ${config.animationDuration} linear infinite`;
        break;
    }

    // Add glow filter when selected
    if (selected && config.selectedGlow) {
      baseStyle.filter = `drop-shadow(0 0 6px ${edgeColor})`;
    }

    return baseStyle;
  };

  // Get animation name for the edge
  const getAnimationName = (): string => {
    switch (config.animationType) {
      case 'flow':
      case 'steady':
        return 'edgeFlow';
      case 'pulse':
        return selected ? 'edgeGlow' : 'edgePulse';
      case 'blink':
        return 'edgeBlink';
      default:
        return '';
    }
  };

  const animationDuration = selected && config.animationType !== 'blink'
    ? `${parseFloat(config.animationDuration) * 0.5}s`
    : config.animationDuration;

  return (
    <>
      {/* Glow layer for selected edges - skip in export mode */}
      {!isExportMode && selected && config.selectedGlow && (
        <path
          d={edgePath}
          fill="none"
          stroke={edgeColor}
          strokeWidth={6}
          strokeOpacity={0.2}
          style={{
            filter: `blur(4px)`,
            pointerEvents: 'none',
          }}
        />
      )}

      <BaseEdge
        id={id}
        path={edgePath}
        style={getAnimationStyle()}
        className={`edge-animation-${getAnimationName()}`}
      />

      <EdgeLabelRenderer>
        <div
          style={{
            position: 'absolute',
            transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
            fontSize: '0.65rem',
            fontWeight: 600,
            pointerEvents: 'all',
            zIndex: 1000,
            opacity: selected ? 1 : 0,
            transition: 'opacity 0.15s ease',
          }}
          className="nodrag nopan"
        >
          <div
            style={{
              background: 'rgba(17, 17, 17, 0.95)',
              border: `1px solid ${edgeColor}`,
              borderRadius: '4px',
              padding: '2px 8px',
              color: edgeColor,
              whiteSpace: 'nowrap',
              boxShadow: selected ? `0 0 12px ${edgeColor}40` : '0 2px 8px rgba(0, 0, 0, 0.4)',
              fontSize: '0.6rem',
              transition: 'box-shadow 0.15s ease',
            }}
            title={config.description}
          >
            {edgeTypeLabel}
            {!isExplicit && (
              <span style={{ opacity: 0.6, marginLeft: '4px' }}>Auto</span>
            )}
          </div>
        </div>
      </EdgeLabelRenderer>
    </>
  );
};

export default StrategyEdge;
