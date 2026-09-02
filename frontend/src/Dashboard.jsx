import React from 'react';
import SOCSummaryCharts from './SOCSummaryCharts';
import SOCIncidentQueue from './SOCIncidentQueue';

const Dashboard = () => {
  return (
    <div style={{ animation: 'fadeIn 0.5s ease' }}>
      <div className="dashboard-header">
        <div>
          <h1 className="dashboard-title">SOC Dashboard</h1>
          <p style={{ color: 'var(--text-secondary)', marginTop: '8px' }}>
            Real-time threat monitoring and incident triage
          </p>
        </div>
        <div style={{ display: 'flex', gap: '12px' }}>
          <div className="glass-panel" style={{ padding: '12px 24px', textAlign: 'center' }}>
            <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Active Incidents</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#ef4444' }}>14</div>
          </div>
          <div className="glass-panel" style={{ padding: '12px 24px', textAlign: 'center' }}>
            <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Avg Resolution</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#22c55e' }}>24m</div>
          </div>
        </div>
      </div>

      <SOCSummaryCharts />
      <SOCIncidentQueue />
    </div>
  );
};

export default Dashboard;
