import type { Edge, Node } from '@xyflow/react';
import type { StrategyNodeData } from './types';

export interface SavedDashboard {
  id: string;
  name: string;
  description: string;
  nodes: Node<StrategyNodeData>[];
  edges: Edge[];
  createdAt: string;
  updatedAt: string;
  publishedAt?: string;
  archivedAt?: string;
  version: number;
  status: 'draft' | 'published' | 'archived';
}

export interface DashboardVersion {
  dashboardId: string;
  version: number;
  nodes: Node<StrategyNodeData>[];
  edges: Edge[];
  savedAt: string;
}

const STORAGE_KEY = 'hackfluency_dashboards';
const VERSIONS_KEY = 'hackfluency_dashboard_versions';

function safeStorageGet(key: string): string | null {
  if (typeof window === 'undefined') return null;
  try {
    return localStorage.getItem(key);
  } catch (error) {
    console.error(`Error reading from localStorage [${key}]:`, error);
    return null;
  }
}

function safeStorageSet(key: string, value: string): boolean {
  if (typeof window === 'undefined') return false;
  try {
    localStorage.setItem(key, value);
    return true;
  } catch (error) {
    console.error(`Error writing to localStorage [${key}]:`, error);
    if (error instanceof DOMException && 
        (error.name === 'QuotaExceededError' || error.name === 'NS_ERROR_DOM_QUOTA_REACHED')) {
      alert('Storage limit reached. Please delete old dashboards or versions.');
    }
    return false;
  }
}

// Get all dashboards from localStorage
export function getAllDashboards(): SavedDashboard[] {
  const data = safeStorageGet(STORAGE_KEY);
  if (!data) return [];
  try {
    return JSON.parse(data);
  } catch (error) {
    console.error('Error parsing dashboards from storage:', error);
    return [];
  }
}


// Get active (non-archived) dashboards
export function getActiveDashboards(): SavedDashboard[] {
  return getAllDashboards().filter(d => d.status !== 'archived');
}

// Get archived dashboards
export function getArchivedDashboards(): SavedDashboard[] {
  return getAllDashboards().filter(d => d.status === 'archived');
}

// Get published dashboards only
export function getPublishedDashboards(): SavedDashboard[] {
  return getAllDashboards().filter(d => d.status === 'published');
}

// Get a single dashboard by ID
export function getDashboardById(id: string): SavedDashboard | null {
  const dashboards = getAllDashboards();
  return dashboards.find(d => d.id === id) || null;
}

// Generate a unique ID
function generateId(): string {
  return `dash-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
}


// Generate a URL-friendly slug
export function generateSlug(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '')
    .substring(0, 50);
}

// Save a new dashboard (draft)
export function saveDashboard(
  name: string,
  description: string,
  nodes: Node<StrategyNodeData>[],
  edges: Edge[]
): SavedDashboard {
  const dashboards = getAllDashboards();
  const now = new Date().toISOString();
  
  const newDashboard: SavedDashboard = {
    id: generateId(),
    name,
    description,
    nodes,
    edges,
    createdAt: now,
    updatedAt: now,
    version: 1,
    status: 'draft',
  };
  
  dashboards.push(newDashboard);
  safeStorageSet(STORAGE_KEY, JSON.stringify(dashboards));
  
  // Save version history
  saveVersion(newDashboard.id, 1, nodes, edges);
  
  return newDashboard;
}

// Update an existing dashboard
export function updateDashboard(
  id: string,
  updates: Partial<Pick<SavedDashboard, 'name' | 'description' | 'nodes' | 'edges'>>
): SavedDashboard | null {
  const dashboards = getAllDashboards();
  const index = dashboards.findIndex(d => d.id === id);
  
  if (index === -1) return null;
  
  const dashboard = dashboards[index];
  const now = new Date().toISOString();
  
  // Increment version if content changed
  const contentChanged = updates.nodes || updates.edges;
  const newVersion = contentChanged ? dashboard.version + 1 : dashboard.version;
  
  const updatedDashboard: SavedDashboard = {
    ...dashboard,
    ...updates,
    updatedAt: now,
    version: newVersion,
  };
  
  dashboards[index] = updatedDashboard;
  safeStorageSet(STORAGE_KEY, JSON.stringify(dashboards));
  
  // Save version if content changed
  if (contentChanged) {
    saveVersion(
      id,
      newVersion,
      updates.nodes || dashboard.nodes,
      updates.edges || dashboard.edges
    );
  }
  
  return updatedDashboard;
}

// Publish a dashboard (make it viewable)
export function publishDashboard(id: string): SavedDashboard | null {
  const dashboards = getAllDashboards();
  const index = dashboards.findIndex(d => d.id === id);
  
  if (index === -1) return null;
  
  const now = new Date().toISOString();
  dashboards[index] = {
    ...dashboards[index],
    status: 'published',
    publishedAt: now,
    updatedAt: now,
  };
  
  safeStorageSet(STORAGE_KEY, JSON.stringify(dashboards));
  return dashboards[index];
}

// Archive a dashboard
export function archiveDashboard(id: string): SavedDashboard | null {
  const dashboards = getAllDashboards();
  const index = dashboards.findIndex(d => d.id === id);
  
  if (index === -1) return null;
  
  const now = new Date().toISOString();
  dashboards[index] = {
    ...dashboards[index],
    status: 'archived',
    archivedAt: now,
    updatedAt: now,
  };
  
  safeStorageSet(STORAGE_KEY, JSON.stringify(dashboards));
  return dashboards[index];
}

// Restore an archived dashboard
export function restoreDashboard(id: string): SavedDashboard | null {
  const dashboards = getAllDashboards();
  const index = dashboards.findIndex(d => d.id === id);
  
  if (index === -1) return null;
  
  const now = new Date().toISOString();
  dashboards[index] = {
    ...dashboards[index],
    status: 'draft',
    archivedAt: undefined,
    updatedAt: now,
  };
  
  safeStorageSet(STORAGE_KEY, JSON.stringify(dashboards));
  return dashboards[index];
}

// Permanently delete a dashboard
export function deleteDashboard(id: string): boolean {
  const dashboards = getAllDashboards();
  const filtered = dashboards.filter(d => d.id !== id);
  
  if (filtered.length === dashboards.length) return false;
  
  safeStorageSet(STORAGE_KEY, JSON.stringify(filtered));
  
  // Also delete versions
  deleteVersions(id);
  
  return true;
}


// Version management
function saveVersion(
  dashboardId: string,
  version: number,
  nodes: Node<StrategyNodeData>[],
  edges: Edge[]
): void {
  if (typeof window === 'undefined') return;
  
  const versions = getAllVersions();
  versions.push({
    dashboardId,
    version,
    nodes,
    edges,
    savedAt: new Date().toISOString(),
  });
  
  // Keep only last 10 versions per dashboard
  const filtered = versions.filter(v => v.dashboardId === dashboardId);
  if (filtered.length > 10) {
    const toRemove = filtered.slice(0, filtered.length - 10);
    const remaining = versions.filter(v => 
      v.dashboardId !== dashboardId || !toRemove.includes(v)
    );
    safeStorageSet(VERSIONS_KEY, JSON.stringify(remaining));
  } else {
    safeStorageSet(VERSIONS_KEY, JSON.stringify(versions));
  }
}

function getAllVersions(): DashboardVersion[] {
  const data = safeStorageGet(VERSIONS_KEY);
  if (!data) return [];
  try {
    return JSON.parse(data);
  } catch (error) {
    console.error('Error parsing versions from storage:', error);
    return [];
  }
}

export function getVersionsForDashboard(dashboardId: string): DashboardVersion[] {
  return getAllVersions()
    .filter(v => v.dashboardId === dashboardId)
    .sort((a, b) => b.version - a.version);
}

export function getVersion(dashboardId: string, version: number): DashboardVersion | null {
  return getAllVersions().find(
    v => v.dashboardId === dashboardId && v.version === version
  ) || null;
}

function deleteVersions(dashboardId: string): void {
  const versions = getAllVersions().filter(v => v.dashboardId !== dashboardId);
  safeStorageSet(VERSIONS_KEY, JSON.stringify(versions));
}


// Duplicate a dashboard
export function duplicateDashboard(id: string, newName?: string): SavedDashboard | null {
  const original = getDashboardById(id);
  if (!original) return null;
  
  return saveDashboard(
    newName || `${original.name} (Copy)`,
    original.description,
    original.nodes,
    original.edges
  );
}
