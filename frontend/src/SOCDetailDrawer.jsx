import React from 'react';

const SOCDetailDrawer = ({ incident, isOpen, onClose }) => {
  if (!incident) return null;

  return (
    <div className={`drawer-overlay ${isOpen ? 'open' : ''}`} onClick={onClose}>
      <div className="drawer-content" onClick={(e) => e.stopPropagation()}>
        <div className="drawer-header">
          <div>
            <h2 className="dashboard-title" style={{ fontSize: '1.5rem', marginBottom: '8px' }}>
              Incident Details
            </h2>
            <div style={{ color: 'var(--text-secondary)' }}>ID: {incident.id}</div>
          </div>
          <button className="close-btn" onClick={onClose}>&times;</button>
        </div>

        <div className="detail-section">
          <h4>Verdict & Severity</h4>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span className={`badge ${incident.severity.toLowerCase()}`}>
              {incident.severity}
            </span>
            <span style={{ fontSize: '1.25rem', fontWeight: 'bold' }}>
              Score: {incident.riskScore}/100
            </span>
          </div>
        </div>

        <div className="detail-section">
          <h4>LLM Reasoning</h4>
          <div className="llm-explanation">
            <p>{incident.explanation}</p>
          </div>
        </div>

        <div className="detail-section">
          <h4>Email Metadata</h4>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '8px', fontSize: '0.9rem' }}>
            <div style={{ color: 'var(--text-secondary)' }}>Sender:</div>
            <div>{incident.sender}</div>
            
            <div style={{ color: 'var(--text-secondary)' }}>Subject:</div>
            <div>{incident.subject}</div>
            
            <div style={{ color: 'var(--text-secondary)' }}>Date:</div>
            <div>{incident.date}</div>
          </div>
        </div>

        <div className="detail-section">
          <h4>Authentication (SPF/DKIM/DMARC)</h4>
          <div style={{ display: 'flex', gap: '16px' }}>
            {['SPF', 'DKIM', 'DMARC'].map((auth) => (
              <div key={auth} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <div style={{ 
                  width: '12px', height: '12px', borderRadius: '50%', 
                  background: incident.authStatus[auth] === 'pass' ? '#22c55e' : '#ef4444' 
                }}></div>
                {auth}: {incident.authStatus[auth].toUpperCase()}
              </div>
            ))}
          </div>
        </div>

        <div className="detail-section">
          <h4>Threat Intel Hits</h4>
          {incident.threatIntel.length > 0 ? (
            <ul style={{ paddingLeft: '20px', color: '#fca5a5' }}>
              {incident.threatIntel.map((threat, idx) => (
                <li key={idx} style={{ marginBottom: '8px' }}>
                  <strong>{threat.type}:</strong> {threat.value} ({threat.source})
                </li>
              ))}
            </ul>
          ) : (
            <p style={{ color: 'var(--text-secondary)' }}>No external threat intel matches found.</p>
          )}
        </div>

        <div style={{ marginTop: '32px', display: 'flex', gap: '16px' }}>
          <button style={{ 
            background: 'var(--accent-color)', color: 'white', border: 'none', 
            padding: '12px 24px', borderRadius: '8px', cursor: 'pointer', fontWeight: 'bold' 
          }}>
            Escalate to Tier 2
          </button>
          <button style={{ 
            background: 'transparent', border: '1px solid var(--panel-border)', color: 'var(--text-primary)', 
            padding: '12px 24px', borderRadius: '8px', cursor: 'pointer' 
          }}>
            Mark as False Positive
          </button>
        </div>
      </div>
    </div>
  );
};

export default SOCDetailDrawer;
