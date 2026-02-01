import React, { useState } from 'react';
import { supabase } from '../../lib/supabase';
import './auth.css';

const Login: React.FC = () => {
  const [email, setEmail] = useState('');
  const [emailSent, setEmailSent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleMagicLink = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) return;

    setLoading(true);
    setError(null);

    try {
      const { error } = await supabase.auth.signInWithOtp({
        email,
        options: {
          shouldCreateUser: false, // Only allow existing users
          emailRedirectTo: window.location.href, // Redirect back to this page
        },
      });

      if (error) throw error;

      setEmailSent(true);
    } catch (err: any) {
      console.error('Login error:', err);
      setError(err.message || 'Failed to send login link.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <header className="auth-header">
          <div className="auth-logo">
            <img src="/HFNeon.png" alt="Hackfluency" />
            <span className="auth-logo-text">
              <span className="logo-hack">Hack</span>
              <span className="logo-fluency">fluency</span>
            </span>
          </div>
          <h1 className="auth-title">Strategy Dashboard</h1>
          {emailSent ? (
            <p className="auth-subtitle" style={{ color: '#00D26A' }}>
              Magic Link Sent!
            </p>
          ) : (
            <p className="auth-subtitle">
              Sign in with your email to access dashboards
            </p>
          )}
        </header>

        {error && (
          <div className="auth-alert error">
            {error}
          </div>
        )}

        {emailSent ? (
          <div className="auth-success-state">
            <div className="success-icon">
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#00D26A" strokeWidth="1.5">
                <path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/>
              </svg>
            </div>
            <p className="success-message">
              We've sent a magic link to <strong>{email}</strong>.
            </p>
            <p className="success-instruction">
              You can close this tab now. Click the link in your email to automatically sign in and access the dashboard.
            </p>
            <button 
              className="auth-back-button"
              onClick={() => {
                setEmailSent(false);
                setError(null);
              }}
            >
              Use a different email
            </button>
          </div>
        ) : (
          <form className="auth-form" onSubmit={handleMagicLink}>
            <div className="auth-form-group">
              <label htmlFor="email" className="auth-label">Email Address</label>
              <input
                type="email"
                id="email"
                className="auth-input"
                placeholder="name@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoFocus
              />
            </div>
            <button type="submit" className="auth-button" disabled={loading}>
              {loading ? <div className="spinner-small" /> : 'Send Magic Link'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
};

export default Login;

