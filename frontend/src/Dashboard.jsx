import React, { useState, useEffect, useCallback } from 'react';
import SOCSummaryCharts from './SOCSummaryCharts';
import SOCIncidentQueue from './SOCIncidentQueue';

const Dashboard = () => {
  const [summary, setSummary] = useState({
    active_incidents: '0',
    emails_scanned: '0',
    threat_rate: '0.0%',
  });
  const [loading, setLoading] = useState(true);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  const fetchSummary = useCallback(async () => {
    try {
      let res;
      try {
        res = await fetch('/api/stats/summary');
      } catch {
        res = await fetch('http://localhost:8000/api/stats/summary');
      }
      if (res.ok) {
        const data = await res.json();
        setSummary({
          active_incidents: String(data.active_incidents ?? 0),
          emails_scanned: Number(data.emails_scanned ?? 0).toLocaleString(),
          threat_rate: String(data.threat_rate || '0.0%'),
        });
      }
    } catch (err) {
      console.warn('Could not fetch live SOC summary, using baseline:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSummary();
    const interval = setInterval(fetchSummary, 15000); // Polling every 15s
    return () => clearInterval(interval);
  }, [fetchSummary, refreshTrigger]);

  const handleIncidentUpdated = () => {
    setRefreshTrigger((prev) => prev + 1);
  };

  const stats = [
    { label: 'Active Incidents', value: summary.active_incidents, color: '#ef4444', icon: '🔴' },
    { label: 'Emails Scanned', value: summary.emails_scanned, color: '#6366f1', icon: '📨' },
    { label: 'Threat Rate', value: summary.threat_rate, color: '#f97316', icon: '🎯' },
  ];

  return (
    <div style={{ animation: 'fadeIn 0.5s ease' }}>
      <div className="dashboard-header">
        <div>
          <h1 className="dashboard-title">SOC Dashboard</h1>
          <p style={{ color: 'var(--text-secondary)', marginTop: '6px', fontSize: '0.92rem' }}>
            Real-time threat monitoring, pipeline triage, and incident lifecycle
          </p>
        </div>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '8px 16px',
          background: 'rgba(34, 197, 94, 0.1)',
          border: '1px solid rgba(34, 197, 94, 0.2)',
          borderRadius: '999px',
          fontSize: '0.8rem',
          color: '#86efac',
          fontWeight: 600,
        }}>
          <span style={{
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            background: '#22c55e',
            animation: 'badge-critical-pulse 2s ease-in-out infinite',
            boxShadow: '0 0 6px rgba(34, 197, 94, 0.5)',
          }}></span>
          Live Database Connected
        </div>
      </div>

      {/* Stats Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: '16px',
        marginBottom: '32px',
      }}>
        {stats.map((stat, i) => (
          <div key={stat.label} className="glass-panel" style={{
            padding: '20px 24px',
            animation: `fadeIn 0.4s ease ${i * 0.1}s both`,
            position: 'relative',
            overflow: 'hidden',
          }}>
            <div style={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              height: '2px',
              background: `linear-gradient(90deg, transparent, ${stat.color}, transparent)`,
              opacity: 0.6,
            }} />
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}>
              <div>
                <div style={{
                  fontSize: '0.75rem',
                  color: 'var(--text-muted)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.08em',
                  fontWeight: 600,
                  marginBottom: '8px',
                }}>
                  {stat.label}
                </div>
                <div style={{
                  fontSize: '1.75rem',
                  fontWeight: 800,
                  color: stat.color,
                  letterSpacing: '-1px',
                  lineHeight: 1,
                  opacity: loading ? 0.7 : 1,
                  transition: 'opacity 0.2s ease',
                }}>
                  {stat.value}
                </div>
              </div>
              <div style={{
                fontSize: '1.5rem',
                opacity: 0.8,
              }}>
                {stat.icon}
              </div>
            </div>
          </div>
        ))}
      </div>

      <SOCSummaryCharts refreshTrigger={refreshTrigger} />
      <SOCIncidentQueue onIncidentUpdated={handleIncidentUpdated} />
    </div>
  );
};

export default Dashboard;
