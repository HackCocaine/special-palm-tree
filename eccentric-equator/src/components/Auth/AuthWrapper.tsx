import React, { useState, useEffect, useCallback } from 'react';
import { supabase } from '../../lib/supabase';
import Login from './Login';
import type { Session } from '@supabase/supabase-js';
import { AuthProvider } from './AuthContext';
import type { SavedDashboard } from '../DashboardBuilder/dashboardStorage';

interface AuthWrapperProps {
  children: React.ReactNode;
  allowPublic?: boolean;
}

function AuthWrapper({ children, allowPublic = false }: AuthWrapperProps) {
  const [session, setSession] = useState<Session | null>(null);
  const [authorizedDashboards, setAuthorizedDashboards] = useState<Set<string>>(new Set());
  const [dashboards, setDashboards] = useState<SavedDashboard[]>([]);
  const [loading, setLoading] = useState(true);
  const [authChecking, setAuthChecking] = useState(false);

  const getDashboardById = useCallback((id: string): SavedDashboard | null => {
    return dashboards.find(d => d.id === id) || null;
  }, [dashboards]);

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      if (!session) setLoading(false);
    });

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session);
      if (!session) setLoading(false);

      if (session && window.location.hash && window.location.hash.includes('access_token')) {
        window.history.replaceState(
          null,
          '',
          window.location.pathname + window.location.search
        );
      }
    });

    return () => subscription.unsubscribe();
  }, []);

  useEffect(() => {
    if (!session) {
      setAuthorizedDashboards(new Set());
      setDashboards([]);
      return;
    }

    const fetchDashboards = async () => {

      setAuthChecking(true);
      try {
        const { data: accessData, error: accessError } = await supabase
          .from('dashboard_access')
          .select('dashboard_id');

        if (accessError) {
          console.error('Error fetching authorizations:', accessError);
          setAuthorizedDashboards(new Set());
          setDashboards([]);
          return;
        }

        const authorizedIds = accessData.map(row => row.dashboard_id);
        setAuthorizedDashboards(new Set(authorizedIds));

        if (authorizedIds.length === 0) {
          setDashboards([]);
          return;
        }

        const { data: dashboardData, error: dashboardError } = await supabase
          .from('dashboards')
          .select('id, title, status, version, payload')
          .in('id', authorizedIds);

        if (dashboardError) {
          console.error('Error fetching dashboard data:', dashboardError);
          setDashboards([]);
        } else if (dashboardData) {
          const parsedDashboards: SavedDashboard[] = dashboardData.map(row => {
            const payload = row.payload as Record<string, unknown>;
            const statusMap: Record<number, SavedDashboard['status']> = { 0: 'draft', 1: 'published' };
            return {
              id: row.id,
              name: row.title || (payload.name as string) || (payload.title as string) || 'Untitled Dashboard',
              description: (payload.description as string) || '',
              nodes: (payload.nodes as SavedDashboard['nodes']) || [],
              edges: (payload.edges as SavedDashboard['edges']) || [],
              createdAt: (payload.createdAt as string) || (payload.created_at as string) || new Date().toISOString(),
              updatedAt: (payload.updatedAt as string) || (payload.updated_at as string) || new Date().toISOString(),
              publishedAt: (payload.publishedAt as string) || (payload.published_at as string),
              archivedAt: (payload.archivedAt as string) || (payload.archived_at as string),
              version: row.version || (payload.version as number) || 1,
              status: statusMap[row.status as number] || (payload.status as SavedDashboard['status']) || 'draft',
            };
          });
          setDashboards(parsedDashboards);
        }
      } catch (err) {
        console.error('Authorization fetch failed:', err);
        setAuthorizedDashboards(new Set());
        setDashboards([]);
      } finally {
        setAuthChecking(false);
        setLoading(false);
      }
    };

    if (session) {
      fetchDashboards();
    }
  }, [session]);

  const isAuthorized = (dashboardId: string) => {
    return authorizedDashboards.has(dashboardId);
  };

  if (loading || authChecking) {
    return (
      <div style={{ 
        display: 'flex', 
        flexDirection: 'column',
        alignItems: 'center', 
        justifyContent: 'center', 
        minHeight: '100vh',
        background: '#0a0a0a',
        color: '#6a6a6a',
        fontFamily: 'Inter, sans-serif'
      }}>
        <div style={{
          width: '40px',
          height: '40px',
          border: '3px solid #2a2a2a',
          borderTopColor: '#00D26A',
          borderRadius: '50%',
          animation: 'spin 1s linear infinite',
          marginBottom: '16px'
        }} />
        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        <span>Verifying access...</span>
      </div>
    );
  }

  if (!session && !allowPublic) {
    return <Login />;
  }

  return (
    <AuthProvider value={{ session, authorizedDashboards, isAuthorized, loading, dashboards, getDashboardById }}>
      {children}
    </AuthProvider>
  );
}

export default AuthWrapper;
