import React, { useState } from 'react';
import SOCDetailDrawer from './SOCDetailDrawer';

// Mock Data
const MOCK_INCIDENTS = [
  {
    id: 'INC-9042',
    date: '2026-09-02 14:22:00',
    sender: 'admin@paypal-security-update.com',
    subject: 'Action Required: Your account has been suspended',
    severity: 'CRITICAL',
    status: 'Open',
    riskScore: 98,
    explanation: 'The LLM detected a high sense of urgency combined with a deceptive sender domain. The domain "paypal-security-update.com" was registered recently and is not affiliated with PayPal. Furthermore, the URL in the body points to a known credential harvesting endpoint.',
    authStatus: { SPF: 'fail', DKIM: 'fail', DMARC: 'fail' },
    threatIntel: [{ type: 'Domain', value: 'paypal-security-update.com', source: 'VirusTotal' }]
  },
  {
    id: 'INC-9041',
    date: '2026-09-02 13:45:11',
    sender: 'hr@internal-corp.net',
    subject: 'Q3 Bonus Payout Schedule - Review Document',
    severity: 'HIGH',
    status: 'Investigating',
    riskScore: 85,
    explanation: 'Contains a macro-enabled Excel attachment masquerading as a bonus schedule. The sender email spoofed an internal HR address, but SPF checks failed indicating the origin server was unauthorized.',
    authStatus: { SPF: 'fail', DKIM: 'pass', DMARC: 'fail' },
    threatIntel: [{ type: 'IP', value: '192.168.x.x', source: 'AbuseIPDB' }]
  },
  {
    id: 'INC-9040',
    date: '2026-09-02 11:10:05',
    sender: 'marketing@newsletter.com',
    subject: 'Weekly Marketing Digest',
    severity: 'LOW',
    status: 'Closed',
    riskScore: 12,
    explanation: 'Standard promotional email. All authentication passed and no malicious links or indicators were found.',
    authStatus: { SPF: 'pass', DKIM: 'pass', DMARC: 'pass' },
    threatIntel: []
  },
  {
    id: 'INC-9039',
    date: '2026-09-01 16:30:22',
    sender: 'it-support@company.com',
    subject: 'Password Expiry Notice',
    severity: 'MEDIUM',
    status: 'Open',
    riskScore: 65,
    explanation: 'The sender is a legitimate internal address, but the email contains a link to an external unverified form for password reset. Flagged for review.',
    authStatus: { SPF: 'pass', DKIM: 'pass', DMARC: 'pass' },
    threatIntel: []
  }
];

const SOCIncidentQueue = () => {
  const [incidents, setIncidents] = useState(MOCK_INCIDENTS);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIncident, setSelectedIncident] = useState(null);

  const filteredIncidents = incidents.filter(inc => {
    const matchesSeverity = filterSeverity === 'ALL' || inc.severity === filterSeverity;
    const matchesSearch = inc.subject.toLowerCase().includes(searchQuery.toLowerCase()) || 
                          inc.sender.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSeverity && matchesSearch;
  });

  return (
    <div className="glass-panel">
      <div className="dashboard-header" style={{ marginBottom: '16px' }}>
        <h3 className="chart-title" style={{ margin: 0 }}>Incident Queue</h3>
      </div>
      
      <div className="controls-bar">
        <input 
          type="text" 
          placeholder="Search by sender or subject..." 
          className="search-input"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />
        <select 
          className="filter-select"
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value)}
        >
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
      </div>

      <div className="incident-table-wrapper">
        <table className="incident-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Date</th>
              <th>Sender</th>
              <th>Subject</th>
              <th>Severity</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {filteredIncidents.map(inc => (
              <tr key={inc.id} onClick={() => setSelectedIncident(inc)}>
                <td>{inc.id}</td>
                <td style={{ color: 'var(--text-secondary)' }}>{inc.date}</td>
                <td>{inc.sender}</td>
                <td>{inc.subject}</td>
                <td><span className={`badge ${inc.severity.toLowerCase()}`}>{inc.severity}</span></td>
                <td style={{ color: 'var(--text-secondary)' }}>{inc.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {filteredIncidents.length === 0 && (
          <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-secondary)' }}>
            No incidents match your criteria.
          </div>
        )}
      </div>

      <SOCDetailDrawer 
        incident={selectedIncident} 
        isOpen={!!selectedIncident} 
        onClose={() => setSelectedIncident(null)} 
      />
    </div>
  );
};

export default SOCIncidentQueue;
