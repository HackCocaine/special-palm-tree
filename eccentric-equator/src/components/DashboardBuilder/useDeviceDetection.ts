import { useState, useEffect, useCallback } from 'react';

/**
 * Device type based on screen size
 * - mobile: < 768px (phones)
 * - tablet: 768px - 1024px (tablets)
 * - desktop: > 1024px (desktops/laptops)
 */
export type DeviceType = 'mobile' | 'tablet' | 'desktop';

export interface DeviceInfo {
  type: DeviceType;
  width: number;
  height: number;
  isTouch: boolean;
  pixelRatio: number;
}

/**
 * Breakpoints matching common device sizes
 */
export const BREAKPOINTS = {
  mobile: 768,
  tablet: 1024,
};

/**
 * Detect the current device type based on screen width
 */
function getDeviceType(width: number): DeviceType {
  if (width < BREAKPOINTS.mobile) {
    return 'mobile';
  } else if (width < BREAKPOINTS.tablet) {
    return 'tablet';
  }
  return 'desktop';
}

/**
 * Hook to detect device information including type, dimensions, and touch capability
 */
export function useDeviceDetection(): DeviceInfo {
  const [deviceInfo, setDeviceInfo] = useState<DeviceInfo>(() => {
    if (typeof window === 'undefined') {
      return {
        type: 'desktop',
        width: 1440,
        height: 900,
        isTouch: false,
        pixelRatio: 1,
      };
    }
    
    return {
      type: getDeviceType(window.innerWidth),
      width: window.innerWidth,
      height: window.innerHeight,
      isTouch: isTouchDevice(),
      pixelRatio: window.devicePixelRatio || 1,
    };
  });

  // Check if device supports touch events
  function isTouchDevice(): boolean {
    if (typeof window === 'undefined') return false;
    
    // Check for touch capability
    if ('ontouchstart' in window || (window as any).navigator.maxTouchPoints > 0) {
      return true;
    }
    
    // Check for touch capability in media query
    if ((window as any).matchMedia && (window as any).matchMedia('(pointer: coarse)').matches) {
      return true;
    }
    
    return false;
  }

  // Handle resize events
  useEffect(() => {
    if (typeof window === 'undefined') return;

    let timeoutId: NodeJS.Timeout | null = null;

    const handleResize = () => {
      // Debounce resize events to avoid excessive updates
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
      
      timeoutId = setTimeout(() => {
        const width = window.innerWidth;
        const height = window.innerHeight;
        const isTouch = isTouchDevice();
        const pixelRatio = window.devicePixelRatio || 1;
        const type = getDeviceType(width);
        
        setDeviceInfo({
          type,
          width,
          height,
          isTouch,
          pixelRatio,
        });
      }, 100);
    };

    // Initial check
    handleResize();

    // Listen for resize events
    window.addEventListener('resize', handleResize);
    
    // Listen for orientation changes (mobile/tablet)
    window.addEventListener('orientationchange', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('orientationchange', handleResize);
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
    };
  }, []);

  return deviceInfo;
}

/**
 * Hook to get ReactFlow configuration based on device type
 */
export function useReactFlowConfig(deviceInfo: DeviceInfo) {
  return useCallback(() => {
    const { type, width } = deviceInfo;
    
    // Calculate optimal viewport based on device
    const baseZoom = 1.38;
    
    if (type === 'mobile') {
      // Mobile: Allow zoom and pan for navigation
      return {
        panOnDrag: true,
        zoomOnScroll: true,
        zoomOnPinch: true,
        zoomOnDoubleClick: true,
        minZoom: 0.5,
        maxZoom: 2,
        defaultZoom: 0.8, // Start zoomed out on mobile
        defaultViewport: { x: -15, y: 0, zoom: 0.8 },
        fitView: false,
        fitViewOptions: { padding: 0.05, maxZoom: 1.0 },
        // Allow full pan extent on mobile
        translateExtent: [[-500, -500], [2000, 2000]],
      };
    } else if (type === 'tablet') {
      // Tablet: Allow zoom and pan with some limits
      return {
        panOnDrag: true,
        zoomOnScroll: true,
        zoomOnPinch: true,
        zoomOnDoubleClick: true,
        minZoom: 0.7,
        maxZoom: 1.5,
        defaultZoom: 1.0,
        defaultViewport: { x: -15, y: -15, zoom: 1.0 },
        fitView: false,
        fitViewOptions: { padding: 0.1, maxZoom: 1.0 },
        // Allow more pan extent on tablet
        translateExtent: [[-200, -200], [1700, 1500]],
      };
    } else {
      // Desktop: Fixed view for better UX
      return {
        panOnDrag: false,
        zoomOnScroll: false,
        zoomOnPinch: false,
        zoomOnDoubleClick: false,
        minZoom: 1.38,
        maxZoom: 1.38,
        defaultZoom: 1.38,
        defaultViewport: { x: -15, y: -15, zoom: 1.38 },
        fitView: true,
        fitViewOptions: { padding: 0.15, maxZoom: 1.0 },
        // Fixed extent for desktop
        translateExtent: [[0, 0], [1490, 1000]],
      };
    }
  }, [deviceInfo]);
}

/**
 * Hook to get CSS class for container based on device
 */
export function useDeviceContainerClass(deviceInfo: DeviceInfo): string {
  return deviceInfo.type;
}
