import React, { useState, useEffect } from 'react';
import { supabase } from '../../lib/supabase';
import Login from './Login';
import type { Session } from '@supabase/supabase-js';

interface AuthWrapperProps {
  children: React.ReactNode;
}

const AuthWrapper: React.FC<AuthWrapperProps> = ({ children }) => {
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check active session
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      setLoading(false);
    });

    // Listen for changes
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session);
      setLoading(false);

      // Clean URL hash if we have a session (removes access_token from URL)
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

  if (loading) {
    // Use the existing loading style from the app if possible, or a simple centered spinner
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

  if (!session) {
    return <Login />;
  }

  return <>{children}</>;
};

export default AuthWrapper;
