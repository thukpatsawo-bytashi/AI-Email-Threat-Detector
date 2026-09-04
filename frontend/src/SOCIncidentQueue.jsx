import React, { useState, useEffect, useCallback } from 'react';
import SOCDetailDrawer from './SOCDetailDrawer';

const statusColors = {
  'New': { bg: 'rgba(59, 130, 246, 0.12)', color: '#93c5fd', border: 'rgba(59, 130, 246, 0.3)' },
  'Open': { bg: 'rgba(239, 68, 68, 0.1)', color: '#fca5a5', border: 'rgba(239, 68, 68, 0.25)' },
  'In Review': { bg: 'rgba(234, 179, 8, 0.1)', color: '#fde047', border: 'rgba(234, 179, 8, 0.25)' },
  'Investigating': { bg: 'rgba(234, 179, 8, 0.1)', color: '#fde047', border: 'rgba(234, 179, 8, 0.25)' },
  'Escalated': { bg: 'rgba(168, 85, 247, 0.15)', color: '#d8b4fe', border: 'rgba(168, 85, 247, 0.35)' },
  'False Positive': { bg: 'rgba(148, 163, 184, 0.12)', color: '#94a3b8', border: 'rgba(148, 163, 184, 0.25)' },
  'Closed': { bg: 'rgba(34, 197, 94, 0.1)', color: '#86efac', border: 'rgba(34, 197, 94, 0.25)' },
  'Clean': { bg: 'rgba(34, 197, 94, 0.1)', color: '#86efac', border: 'rgba(34, 197, 94, 0.25)' },
};

const RiskBar = ({ score }) => {
  const numScore = Number(score) || 0;
  const color = numScore >= 80 ? '#ef4444' : numScore >= 60 ? '#f97316' : numScore >= 30 ? '#eab308' : '#22c55e';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: '120px' }}>
      <div style={{
        flex: 1,
        height: '4px',
        background: 'rgba(255,255,255,0.06)',
        borderRadius: '999px',
        overflow: 'hidden',
      }}>
        <div style={{
          width: `${numScore}%`,
          height: '100%',
          background: `linear-gradient(90deg, ${color}88, ${color})`,
          borderRadius: '999px',
          transition: 'width 0.6s cubic-bezier(0.16, 1, 0.3, 1)',
        }} />
      </div>
      <span style={{
        fontSize: '0.75rem',
        fontWeight: 700,
        color,
        minWidth: '28px',
        textAlign: 'right',
        fontVariantNumeric: 'tabular-nums',
      }}>
        {numScore}
      </span>
    </div>
  );
};

const SOCIncidentQueue = ({ onIncidentUpdated }) => {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [selectedIncidents, setSelectedIncidents] = useState(new Set());
  const [bulkDeleting, setBulkDeleting] = useState(false);

  const fetchIncidents = useCallback(async () => {
    try {
      let url = '/api/incidents';
      const params = new URLSearchParams();
      if (filterSeverity !== 'ALL') params.append('severity', filterSeverity);
      if (searchQuery.trim()) params.append('search', searchQuery.trim());
      if (params.toString()) url += `?${params.toString()}`;

      let res;
      try {
        res = await fetch(url);
      } catch {
        res = await fetch(`http://localhost:8000${url}`);
      }

      if (res.ok) {
        const data = await res.json();
        setIncidents(data.items || []);
      }
    } catch (err) {
      console.warn('Could not fetch incidents from backend:', err);
    } finally {
      setLoading(false);
    }
  }, [filterSeverity, searchQuery]);

  useEffect(() => {
    fetchIncidents();
    const interval = setInterval(fetchIncidents, 10000); // Poll every 10s
    return () => clearInterval(interval);
  }, [fetchIncidents]);

  const handleIncidentStatusChanged = (updatedInc) => {
    if (updatedInc && updatedInc.isDeleted) {
      setIncidents(prev => prev.filter(inc => inc.id !== updatedInc.id));
      if (selectedIncident && selectedIncident.id === updatedInc.id) {
        setSelectedIncident(null);
      }
      setSelectedIncidents(prev => {
        const next = new Set(prev);
        next.delete(updatedInc.id);
        return next;
      });
    } else {
      setIncidents(prev => prev.map(inc => (inc.id === updatedInc.id ? updatedInc : inc)));
      if (selectedIncident && selectedIncident.id === updatedInc.id) {
        setSelectedIncident(updatedInc);
      }
    }
    if (onIncidentUpdated) {
      onIncidentUpdated(updatedInc);
    }
    fetchIncidents();
  };

  const toggleSelection = (e, id) => {
    e.stopPropagation();
    const next = new Set(selectedIncidents);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelectedIncidents(next);
  };

  const toggleAll = () => {
    if (selectedIncidents.size === incidents.length && incidents.length > 0) {
      setSelectedIncidents(new Set());
    } else {
      setSelectedIncidents(new Set(incidents.map(i => i.id)));
    }
  };

  const handleBulkDelete = async () => {
    if (selectedIncidents.size === 0) return;
    if (!window.confirm(`Are you sure you want to delete ${selectedIncidents.size} incidents permanently?`)) return;
    setBulkDeleting(true);
    try {
      // Map selected string IDs to numeric IDs
      const numericIds = incidents
        .filter(inc => selectedIncidents.has(inc.id))
        .map(inc => inc.numeric_id || parseInt(String(inc.id).replace(/\D/g, ''), 10));
      
      const res = await fetch('/api/incidents/bulk', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ item_ids: numericIds })
      });
      if (res.ok) {
        setSelectedIncidents(new Set());
        fetchIncidents();
      } else {
        alert('Failed to delete incidents');
      }
    } catch (err) {
      alert('Network error during bulk delete');
    } finally {
      setBulkDeleting(false);
    }
  };

  const severityCounts = incidents.reduce((acc, inc) => {
    const sev = (inc.severity || 'LOW').toUpperCase();
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="glass-panel">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <h3 className="chart-title" style={{ margin: 0 }}>Incident Queue</h3>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            ({incidents.length} total)
          </span>
        </div>
        <div style={{ display: 'flex', gap: '6px' }}>
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
            severityCounts[sev] ? (
              <span key={sev} style={{
                fontSize: '0.65rem',
                padding: '2px 8px',
                borderRadius: '999px',
                fontWeight: 700,
                background: sev === 'CRITICAL' ? 'rgba(239,68,68,0.15)' :
                            sev === 'HIGH' ? 'rgba(249,115,22,0.15)' :
                            sev === 'MEDIUM' ? 'rgba(234,179,8,0.15)' :
                            'rgba(34,197,94,0.15)',
                color: sev === 'CRITICAL' ? '#fca5a5' :
                       sev === 'HIGH' ? '#fdba74' :
                       sev === 'MEDIUM' ? '#fde047' :
                       '#86efac',
              }}>
                {severityCounts[sev]} {sev}
              </span>
            ) : null
          ))}
        </div>
      </div>

      <div className="controls-bar">
        <div style={{ position: 'relative', flex: 1 }}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{
            position: 'absolute',
            left: '12px',
            top: '50%',
            transform: 'translateY(-50%)',
            width: '16px',
            height: '16px',
            color: 'var(--text-muted)',
            pointerEvents: 'none',
          }}>
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <input
            type="text"
            placeholder="Search by ID, sender, or subject..."
            className="search-input"
            style={{ paddingLeft: '36px' }}
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
        <select
          className="filter-select"
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value)}
        >
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">🔴 Critical</option>
          <option value="HIGH">🟠 High</option>
          <option value="MEDIUM">🟡 Medium</option>
          <option value="LOW">🟢 Low</option>
        </select>
        <button
          onClick={fetchIncidents}
          style={{
            background: 'rgba(255, 255, 255, 0.05)',
            border: '1px solid var(--panel-border)',
            color: 'var(--text-secondary)',
            padding: '8px 14px',
            borderRadius: '8px',
            cursor: 'pointer',
            fontSize: '0.82rem',
            fontWeight: 600,
          }}
          title="Refresh incidents"
        >
          ↻ Refresh
        </button>
        {selectedIncidents.size > 0 && (
          <button
            onClick={handleBulkDelete}
            disabled={bulkDeleting}
            style={{
              background: 'rgba(239, 68, 68, 0.15)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              color: '#fca5a5',
              padding: '8px 14px',
              borderRadius: '8px',
              cursor: bulkDeleting ? 'not-allowed' : 'pointer',
              fontSize: '0.82rem',
              fontWeight: 600,
            }}
          >
            {bulkDeleting ? 'Deleting...' : `🗑️ Delete (${selectedIncidents.size})`}
          </button>
        )}
      </div>

      <div className="incident-table-wrapper">
        <table className="incident-table">
          <thead>
            <tr>
              <th style={{ width: '40px', textAlign: 'center' }}>
                <input 
                  type="checkbox" 
                  checked={incidents.length > 0 && selectedIncidents.size === incidents.length}
                  onChange={toggleAll}
                />
              </th>
              <th>ID</th>
              <th>Date</th>
              <th>Sender</th>
              <th>Location</th>
              <th>Subject</th>
              <th>Risk</th>
              <th>Severity</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {incidents.map((inc, i) => {
              const statusStyle = statusColors[inc.status] || statusColors['Clean'];
              return (
                <tr
                  key={inc.id}
                  onClick={() => setSelectedIncident(inc)}
                  style={{ animation: `fadeIn 0.3s ease ${Math.min(i * 0.04, 0.5)}s both` }}
                >
                  <td style={{ textAlign: 'center' }} onClick={(e) => e.stopPropagation()}>
                    <input 
                      type="checkbox" 
                      checked={selectedIncidents.has(inc.id)}
                      onChange={(e) => toggleSelection(e, inc.id)}
                    />
                  </td>
                  <td style={{ fontWeight: 600, color: 'var(--accent-color)', fontSize: '0.82rem' }}>{inc.id}</td>
                  <td style={{ color: 'var(--text-muted)', fontSize: '0.82rem', whiteSpace: 'nowrap' }}>{inc.date}</td>
                  <td style={{ fontFamily: "'SF Mono', 'Fira Code', monospace", fontSize: '0.8rem', color: 'var(--text-secondary)', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{inc.sender}</td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                    {inc.geo && inc.geo.country && inc.geo.country !== 'Unknown'
                      ? `📍 ${inc.geo.city && inc.geo.city !== 'Unknown' ? inc.geo.city + ', ' : ''}${inc.geo.country}`
                      : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                  </td>
                  <td style={{ maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{inc.subject}</td>
                  <td><RiskBar score={inc.riskScore} /></td>
                  <td><span className={`badge ${(inc.severity || 'low').toLowerCase()}`}>{inc.severity}</span></td>
                  <td>
                    <span style={{
                      fontSize: '0.72rem',
                      padding: '3px 10px',
                      borderRadius: '999px',
                      fontWeight: 600,
                      background: statusStyle.bg,
                      color: statusStyle.color,
                      border: `1px solid ${statusStyle.border}`,
                      whiteSpace: 'nowrap',
                    }}>
                      {inc.status}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {incidents.length === 0 && !loading && (
          <div style={{ padding: '56px 24px', textAlign: 'center', color: 'var(--text-muted)' }}>
            <div style={{ fontSize: '2.5rem', marginBottom: '12px' }}>🛡️</div>
            <div style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px' }}>
              {searchQuery || filterSeverity !== 'ALL' ? 'No incidents match your filter criteria.' : 'No security incidents logged yet.'}
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '420px', margin: '0 auto 16px', lineHeight: 1.5 }}>
              {searchQuery || filterSeverity !== 'ALL'
                ? 'Try resetting the severity filter or clearing your search term.'
                : 'Scanned emails with elevated threat signals (suspicious links, phishing language, or authentication failures) will appear here automatically in real time.'}
            </p>
            {(!searchQuery && filterSeverity === 'ALL') && (
              <a
                href="/"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '8px 18px',
                  background: 'var(--accent-color)',
                  color: 'white',
                  borderRadius: 'var(--radius-md)',
                  textDecoration: 'none',
                  fontSize: '0.85rem',
                  fontWeight: 600,
                }}
              >
                Scan an Email Now →
              </a>
            )}
          </div>
        )}
      </div>

      <SOCDetailDrawer
        incident={selectedIncident}
        isOpen={!!selectedIncident}
        onClose={() => setSelectedIncident(null)}
        onStatusUpdated={handleIncidentStatusChanged}
      />
    </div>
  );
};

export default SOCIncidentQueue;
