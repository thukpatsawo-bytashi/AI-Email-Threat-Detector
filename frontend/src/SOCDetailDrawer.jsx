import React, { useState } from 'react';

const SOCDetailDrawer = ({ incident, isOpen, onClose, onStatusUpdated }) => {
  const [updating, setUpdating] = useState(false);
  const [toastMessage, setToastMessage] = useState(null);

  if (!incident) return null;

  const riskColor = incident.riskScore >= 80 ? '#ef4444' :
                    incident.riskScore >= 60 ? '#f97316' :
                    incident.riskScore >= 30 ? '#eab308' : '#22c55e';

  const handleUpdateStatus = async (newStatus) => {
    setUpdating(true);
    setToastMessage(null);
    try {
      const incidentId = incident.numeric_id || parseInt(String(incident.id).replace(/\D/g, ''), 10);
      let res;
      try {
        res = await fetch(`/api/incidents/${incidentId}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: newStatus }),
        });
      } catch {
        res = await fetch(`http://localhost:8000/api/incidents/${incidentId}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: newStatus }),
        });
      }

      if (res.ok) {
        const data = await res.json();
        setToastMessage(`Status updated to ${newStatus.replace('_', ' ').toUpperCase()}!`);
        if (onStatusUpdated && data.incident) {
          onStatusUpdated(data.incident);
        }
      } else {
        const errData = await res.json();
        setToastMessage(`Error: ${errData.detail || 'Failed to update'}`);
      }
    } catch (err) {
      setToastMessage(`Network error updating incident`);
    } finally {
      setUpdating(false);
      setTimeout(() => setToastMessage(null), 4000);
    }
  };

  return (
    <div className={`drawer-overlay ${isOpen ? 'open' : ''}`} onClick={onClose}>
      <div className="drawer-content" onClick={(e) => e.stopPropagation()}>
        <div className="drawer-header">
          <div>
            <h2 className="dashboard-title" style={{ fontSize: '1.35rem', marginBottom: '6px' }}>
              Incident Details
            </h2>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              color: 'var(--text-muted)',
              fontSize: '0.85rem',
            }}>
              <span style={{ fontWeight: 600, color: 'var(--accent-color)' }}>{incident.id}</span>
              <span>•</span>
              <span>{incident.date}</span>
              <span>•</span>
              <span style={{
                padding: '2px 8px',
                borderRadius: '999px',
                fontSize: '0.72rem',
                background: 'rgba(255, 255, 255, 0.08)',
                color: 'var(--text-primary)',
                fontWeight: 600,
              }}>
                Status: {incident.status}
              </span>
            </div>
          </div>
          <button className="close-btn" onClick={onClose}>&times;</button>
        </div>

        {toastMessage && (
          <div style={{
            padding: '10px 16px',
            marginBottom: '16px',
            borderRadius: '8px',
            background: toastMessage.startsWith('Error') ? 'rgba(239, 68, 68, 0.15)' : 'rgba(34, 197, 94, 0.15)',
            border: `1px solid ${toastMessage.startsWith('Error') ? '#ef4444' : '#22c55e'}`,
            color: toastMessage.startsWith('Error') ? '#fca5a5' : '#86efac',
            fontSize: '0.85rem',
            fontWeight: 600,
            animation: 'fadeIn 0.2s ease',
          }}>
            {toastMessage}
          </div>
        )}

        {/* Risk Score Visual */}
        <div className="detail-section" style={{ textAlign: 'center', padding: '28px 20px' }}>
          <h4>Threat Score</h4>
          <div style={{
            position: 'relative',
            width: '120px',
            height: '120px',
            margin: '0 auto 16px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}>
            <svg viewBox="0 0 120 120" style={{ position: 'absolute', inset: 0, transform: 'rotate(-90deg)' }}>
              <circle cx="60" cy="60" r="52" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="6" />
              <circle
                cx="60" cy="60" r="52"
                fill="none"
                stroke={riskColor}
                strokeWidth="6"
                strokeLinecap="round"
                strokeDasharray={`${(incident.riskScore / 100) * 327} 327`}
                style={{
                  filter: `drop-shadow(0 0 6px ${riskColor}60)`,
                  transition: 'stroke-dasharray 1s cubic-bezier(0.16, 1, 0.3, 1)',
                }}
              />
            </svg>
            <div>
              <div style={{
                fontSize: '2rem',
                fontWeight: 900,
                color: riskColor,
                letterSpacing: '-2px',
                lineHeight: 1,
              }}>
                {incident.riskScore}
              </div>
              <div style={{
                fontSize: '0.65rem',
                color: 'var(--text-muted)',
                textTransform: 'uppercase',
                letterSpacing: '1.5px',
                marginTop: '2px',
              }}>
                Risk
              </div>
            </div>
          </div>
          <span className={`badge ${(incident.severity || 'low').toLowerCase()}`} style={{ fontSize: '0.75rem', padding: '5px 14px' }}>
            {incident.severity}
          </span>
        </div>

        {/* LLM Reasoning */}
        <div className="detail-section">
          <h4>Analysis Reasoning & Findings</h4>
          <div className="llm-explanation">
            <p>{incident.explanation}</p>
          </div>
        </div>

        {/* Email Metadata */}
        <div className="detail-section">
          <h4>Email Metadata</h4>
          <div style={{ display: 'grid', gridTemplateColumns: '100px 1fr', gap: '10px 16px', fontSize: '0.875rem' }}>
            <div style={{ color: 'var(--text-muted)', fontWeight: 500 }}>Sender</div>
            <div style={{
              fontFamily: "'SF Mono', 'Fira Code', monospace",
              fontSize: '0.82rem',
              color: 'var(--text-secondary)',
              wordBreak: 'break-all',
            }}>{incident.sender}</div>

            <div style={{ color: 'var(--text-muted)', fontWeight: 500 }}>Subject</div>
            <div style={{ color: 'var(--text-primary)' }}>{incident.subject}</div>

            <div style={{ color: 'var(--text-muted)', fontWeight: 500 }}>Date</div>
            <div style={{ color: 'var(--text-secondary)' }}>{incident.date}</div>
          </div>
        </div>

        {/* Auth Status */}
        <div className="detail-section">
          <h4>Authentication Status</h4>
          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            {['SPF', 'DKIM', 'DMARC'].map((auth) => {
              const status = incident.authStatus?.[auth] || 'none';
              const passed = status.toLowerCase() === 'pass';
              return (
                <div key={auth} style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '8px 14px',
                  background: passed ? 'rgba(34, 197, 94, 0.08)' : 'rgba(239, 68, 68, 0.08)',
                  border: `1px solid ${passed ? 'rgba(34, 197, 94, 0.2)' : 'rgba(239, 68, 68, 0.2)'}`,
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.8rem',
                  fontWeight: 600,
                }}>
                  <div style={{
                    width: '8px',
                    height: '8px',
                    borderRadius: '50%',
                    background: passed ? '#22c55e' : '#ef4444',
                    boxShadow: `0 0 6px ${passed ? 'rgba(34,197,94,0.4)' : 'rgba(239,68,68,0.4)'}`,
                  }} />
                  <span style={{ color: 'var(--text-muted)' }}>{auth}</span>
                  <span style={{ color: passed ? '#86efac' : '#fca5a5' }}>
                    {status.toUpperCase()}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Threat Intel */}
        <div className="detail-section">
          <h4>Threat Intelligence Hits</h4>
          {incident.threatIntel && incident.threatIntel.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {incident.threatIntel.map((threat, idx) => (
                <div key={idx} style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                  padding: '12px 16px',
                  background: 'rgba(239, 68, 68, 0.06)',
                  border: '1px solid rgba(239, 68, 68, 0.15)',
                  borderRadius: 'var(--radius-sm)',
                }}>
                  <span style={{
                    fontSize: '0.65rem',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    padding: '2px 8px',
                    background: 'rgba(239, 68, 68, 0.15)',
                    color: '#fca5a5',
                    borderRadius: '4px',
                    letterSpacing: '0.5px',
                  }}>
                    {threat.type}
                  </span>
                  <span style={{
                    flex: 1,
                    fontFamily: "'SF Mono', 'Fira Code', monospace",
                    fontSize: '0.82rem',
                    color: '#fca5a5',
                  }}>
                    {threat.value}
                  </span>
                  <span style={{
                    fontSize: '0.7rem',
                    color: 'var(--text-muted)',
                    fontWeight: 500,
                  }}>
                    via {threat.source}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div style={{
              padding: '20px',
              textAlign: 'center',
              color: 'var(--text-muted)',
              fontSize: '0.85rem',
            }}>
              <span style={{ fontSize: '1.2rem', display: 'block', marginBottom: '6px' }}>✅</span>
              No external malicious threat intel indicators matched.
            </div>
          )}
        </div>

        {/* Real Triage Actions */}
        <div style={{ marginTop: '24px' }}>
          <h4 style={{
            fontSize: '0.75rem',
            fontWeight: 700,
            textTransform: 'uppercase',
            letterSpacing: '0.1em',
            color: 'var(--text-muted)',
            marginBottom: '12px',
          }}>
            Triage Actions
          </h4>
          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
            <button
              disabled={updating}
              onClick={() => handleUpdateStatus('escalated')}
              style={{
                flex: 1,
                minWidth: '160px',
                background: 'linear-gradient(135deg, #a855f7, #6366f1)',
                color: 'white',
                border: 'none',
                padding: '12px 20px',
                borderRadius: 'var(--radius-md)',
                cursor: updating ? 'not-allowed' : 'pointer',
                fontWeight: 700,
                fontFamily: 'var(--font-family)',
                fontSize: '0.85rem',
                transition: 'all 0.2s ease',
                boxShadow: '0 4px 14px rgba(168, 85, 247, 0.25)',
                opacity: updating ? 0.6 : 1,
              }}
            >
              {updating ? 'Updating...' : '⚡ Escalate to Tier 2'}
            </button>

            <button
              disabled={updating}
              onClick={() => handleUpdateStatus('false_positive')}
              style={{
                flex: 1,
                minWidth: '160px',
                background: 'rgba(255, 255, 255, 0.05)',
                border: '1px solid var(--panel-border)',
                color: 'var(--text-secondary)',
                padding: '12px 20px',
                borderRadius: 'var(--radius-md)',
                cursor: updating ? 'not-allowed' : 'pointer',
                fontFamily: 'var(--font-family)',
                fontSize: '0.85rem',
                fontWeight: 600,
                transition: 'all 0.2s ease',
                opacity: updating ? 0.6 : 1,
              }}
            >
              {updating ? 'Updating...' : 'Mark as False Positive'}
            </button>

            <button
              disabled={updating}
              onClick={() => handleUpdateStatus('closed')}
              style={{
                background: 'rgba(34, 197, 94, 0.1)',
                border: '1px solid rgba(34, 197, 94, 0.3)',
                color: '#86efac',
                padding: '12px 18px',
                borderRadius: 'var(--radius-md)',
                cursor: updating ? 'not-allowed' : 'pointer',
                fontFamily: 'var(--font-family)',
                fontSize: '0.85rem',
                fontWeight: 600,
                transition: 'all 0.2s ease',
                opacity: updating ? 0.6 : 1,
              }}
              title="Close and resolve incident"
            >
              ✓ Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SOCDetailDrawer;
