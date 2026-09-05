import React, { useState, useEffect } from 'react';

const IMAPMonitor = () => {
  const [config, setConfig] = useState({
    host: '',
    port: 993,
    email: '',
    password: '',
    folder: 'INBOX',
    interval: 30,
  });
  const [status, setStatus] = useState({
    active: false,
    emails_processed: 0,
    last_check: null,
    error: null,
    connected_to: null,
  });
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState(null);

  const fetchStatus = async () => {
    try {
      const res = await fetch('/api/imap/status');
      if (res.ok) {
        setStatus(await res.json());
      }
    } catch {}
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleStart = async () => {
    setSubmitting(true);
    setMessage(null);
    try {
      const res = await fetch('/api/imap/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      });
      const data = await res.json();
      setMessage(data.message);
      fetchStatus();
    } catch (err) {
      setMessage('Network error starting monitor');
    } finally {
      setSubmitting(false);
    }
  };

  const handleStop = async () => {
    setSubmitting(true);
    setMessage(null);
    try {
      const res = await fetch('/api/imap/stop', { method: 'POST' });
      const data = await res.json();
      setMessage(data.message);
      fetchStatus();
    } catch (err) {
      setMessage('Network error stopping monitor');
    } finally {
      setSubmitting(false);
    }
  };

  const inputStyle = {
    width: '100%',
    padding: '10px 14px',
    background: 'rgba(15, 23, 42, 0.6)',
    border: '1px solid rgba(255,255,255,0.1)',
    borderRadius: '8px',
    color: '#e2e8f0',
    fontSize: '0.85rem',
    fontFamily: "'Inter', 'SF Pro Display', sans-serif",
    outline: 'none',
    transition: 'border-color 0.2s ease',
  };

  const labelStyle = {
    fontSize: '0.75rem',
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    color: 'var(--text-muted)',
    marginBottom: '6px',
    display: 'block',
  };

  return (
    <div style={{ animation: 'fadeIn 0.5s ease' }}>
      <div className="dashboard-header">
        <div>
          <h1 className="dashboard-title">Live Email Monitor</h1>
          <p style={{ color: 'var(--text-secondary)', marginTop: '6px', fontSize: '0.92rem' }}>
            Connect to your IMAP inbox for real-time email analysis
          </p>
        </div>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '8px 16px',
          background: status.active ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)',
          border: `1px solid ${status.active ? 'rgba(34, 197, 94, 0.2)' : 'rgba(239, 68, 68, 0.2)'}`,
          borderRadius: '999px',
          fontSize: '0.8rem',
          color: status.active ? '#86efac' : '#fca5a5',
          fontWeight: 600,
        }}>
          <span style={{
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            background: status.active ? '#22c55e' : '#ef4444',
            animation: status.active ? 'badge-critical-pulse 2s ease-in-out infinite' : 'none',
            boxShadow: status.active ? '0 0 6px rgba(34, 197, 94, 0.5)' : 'none',
          }}></span>
          {status.active ? 'Monitoring Active' : 'Monitoring Stopped'}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
        {/* Config Panel */}
        <div className="glass-panel" style={{ padding: '28px' }}>
          <h3 style={{
            fontSize: '1rem',
            fontWeight: 700,
            marginBottom: '24px',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
          }}>
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="2" y="3" width="20" height="14" rx="2" />
              <line x1="8" y1="21" x2="16" y2="21" />
              <line x1="12" y1="17" x2="12" y2="21" />
            </svg>
            IMAP Configuration
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '12px' }}>
              <div>
                <label style={labelStyle}>IMAP Host</label>
                <input
                  type="text"
                  value={config.host}
                  onChange={e => setConfig({ ...config, host: e.target.value })}
                  placeholder="imap.gmail.com"
                  style={inputStyle}
                  disabled={status.active}
                />
              </div>
              <div>
                <label style={labelStyle}>Port</label>
                <input
                  type="number"
                  value={config.port}
                  onChange={e => setConfig({ ...config, port: parseInt(e.target.value) || 993 })}
                  style={inputStyle}
                  disabled={status.active}
                />
              </div>
            </div>

            <div>
              <label style={labelStyle}>Email Address</label>
              <input
                type="email"
                value={config.email}
                onChange={e => setConfig({ ...config, email: e.target.value })}
                placeholder="analyst@company.com"
                style={inputStyle}
                disabled={status.active}
              />
            </div>

            <div>
              <label style={labelStyle}>Password / App Password</label>
              <input
                type="password"
                value={config.password}
                onChange={e => setConfig({ ...config, password: e.target.value })}
                placeholder="••••••••••••"
                style={inputStyle}
                disabled={status.active}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div>
                <label style={labelStyle}>Folder</label>
                <input
                  type="text"
                  value={config.folder}
                  onChange={e => setConfig({ ...config, folder: e.target.value })}
                  placeholder="INBOX"
                  style={inputStyle}
                  disabled={status.active}
                />
              </div>
              <div>
                <label style={labelStyle}>Poll Interval (seconds)</label>
                <input
                  type="number"
                  value={config.interval}
                  onChange={e => setConfig({ ...config, interval: parseInt(e.target.value) || 30 })}
                  min={10}
                  style={inputStyle}
                  disabled={status.active}
                />
              </div>
            </div>

            <div style={{ display: 'flex', gap: '12px', marginTop: '8px' }}>
              {!status.active ? (
                <button
                  onClick={handleStart}
                  disabled={submitting || !config.host || !config.email || !config.password}
                  style={{
                    flex: 1,
                    padding: '12px 20px',
                    background: 'rgba(34, 197, 94, 0.15)',
                    border: '1px solid rgba(34, 197, 94, 0.3)',
                    color: '#86efac',
                    borderRadius: '10px',
                    cursor: submitting ? 'not-allowed' : 'pointer',
                    fontFamily: "'Inter', sans-serif",
                    fontSize: '0.9rem',
                    fontWeight: 700,
                    transition: 'all 0.2s ease',
                    opacity: submitting || !config.host || !config.email || !config.password ? 0.5 : 1,
                  }}
                >
                  {submitting ? 'Connecting...' : '▶ Start Monitoring'}
                </button>
              ) : (
                <button
                  onClick={handleStop}
                  disabled={submitting}
                  style={{
                    flex: 1,
                    padding: '12px 20px',
                    background: 'rgba(239, 68, 68, 0.15)',
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                    color: '#fca5a5',
                    borderRadius: '10px',
                    cursor: submitting ? 'not-allowed' : 'pointer',
                    fontFamily: "'Inter', sans-serif",
                    fontSize: '0.9rem',
                    fontWeight: 700,
                    transition: 'all 0.2s ease',
                  }}
                >
                  {submitting ? 'Stopping...' : '⏹ Stop Monitoring'}
                </button>
              )}
            </div>

            {message && (
              <div style={{
                padding: '10px 14px',
                background: 'rgba(99, 102, 241, 0.1)',
                border: '1px solid rgba(99, 102, 241, 0.2)',
                borderRadius: '8px',
                fontSize: '0.82rem',
                color: '#c7d2fe',
              }}>
                {message}
              </div>
            )}
          </div>
        </div>

        {/* Live Status Panel */}
        <div className="glass-panel" style={{ padding: '28px' }}>
          <h3 style={{
            fontSize: '1rem',
            fontWeight: 700,
            marginBottom: '24px',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
          }}>
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
            </svg>
            Live Status
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            {/* Status Indicator */}
            <div style={{
              padding: '20px',
              background: status.active ? 'rgba(34, 197, 94, 0.06)' : 'rgba(148, 163, 184, 0.06)',
              border: `1px solid ${status.active ? 'rgba(34, 197, 94, 0.15)' : 'rgba(148, 163, 184, 0.15)'}`,
              borderRadius: '12px',
              textAlign: 'center',
            }}>
              <div style={{ fontSize: '2.5rem', marginBottom: '8px', color: status.active ? '#86efac' : 'var(--text-muted)' }}>
                {status.active ? (
                  <svg viewBox="0 0 24 24" width="36" height="36" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
                  </svg>
                ) : (
                  <svg viewBox="0 0 24 24" width="36" height="36" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="10" />
                    <line x1="4.93" y1="4.93" x2="19.07" y2="19.07" />
                  </svg>
                )}
              </div>
              <div style={{
                fontSize: '1.1rem',
                fontWeight: 700,
                color: status.active ? '#86efac' : 'var(--text-muted)',
              }}>
                {status.active ? 'Connected & Monitoring' : 'Disconnected'}
              </div>
              {status.connected_to && (
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                  {status.connected_to}
                </div>
              )}
            </div>

            {/* Metrics */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div style={{
                padding: '16px',
                background: 'rgba(99, 102, 241, 0.06)',
                border: '1px solid rgba(99, 102, 241, 0.15)',
                borderRadius: '10px',
                textAlign: 'center',
              }}>
                <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#a78bfa' }}>
                  {status.emails_processed}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Emails Processed
                </div>
              </div>
              <div style={{
                padding: '16px',
                background: 'rgba(34, 197, 94, 0.06)',
                border: '1px solid rgba(34, 197, 94, 0.15)',
                borderRadius: '10px',
                textAlign: 'center',
              }}>
                <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#86efac', marginBottom: '4px' }}>
                  {status.last_check || '—'}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Last Check
                </div>
              </div>
            </div>

            {/* Error Display */}
            {status.error && (
              <div style={{
                padding: '12px 16px',
                background: 'rgba(239, 68, 68, 0.08)',
                borderLeft: '4px solid #ef4444',
                borderRadius: '4px',
                fontSize: '0.82rem',
                color: '#fca5a5',
              }}>
                <strong>Error:</strong> {status.error}
              </div>
            )}

            {/* Info */}
            <div style={{
              padding: '14px',
              background: 'rgba(99, 102, 241, 0.04)',
              border: '1px solid rgba(99, 102, 241, 0.1)',
              borderRadius: '8px',
              fontSize: '0.78rem',
              color: 'var(--text-secondary)',
              lineHeight: 1.6,
            }}>
              <strong style={{ color: 'var(--text-primary)' }}>How it works:</strong>
              <br />
              The monitor connects to your IMAP server and polls for new emails at the
              configured interval. Each new email is automatically analyzed through the
              full detection pipeline and appears in the Dashboard incident queue in real time.
              <br /><br />
              <strong>Gmail users:</strong> Use an App Password (not your regular password).
              Enable "Less secure app access" or generate an App Password in Google Account settings.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default IMAPMonitor;
