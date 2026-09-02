import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import Upload from './Upload';

/* ── Circular risk gauge (SVG) ──────────────────────────────────── */
const RiskGauge = ({ score, classification }) => {
  const color = score >= 80 ? '#ef4444' : score >= 60 ? '#f97316' : score >= 30 ? '#eab308' : '#22c55e';
  const circumference = 2 * Math.PI * 56;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="user-risk-gauge">
      <svg viewBox="0 0 128 128" width="160" height="160">
        <circle cx="64" cy="64" r="56" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="8" />
        <circle
          cx="64" cy="64" r="56"
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{
            transform: 'rotate(-90deg)',
            transformOrigin: '50% 50%',
            filter: `drop-shadow(0 0 10px ${color}50)`,
            transition: 'stroke-dashoffset 1.2s cubic-bezier(0.16, 1, 0.3, 1)',
          }}
        />
      </svg>
      <div className="user-risk-gauge-inner">
        <div className="user-risk-gauge-score" style={{ color }}>{score}</div>
        <div className="user-risk-gauge-label">/ 100</div>
      </div>
      <div className={`user-risk-badge ${classification.toLowerCase()}`}>
        {classification}
      </div>
    </div>
  );
};

/* ── Auth badge row ─────────────────────────────────────────────── */
const AuthBadges = ({ spf, dkim, dmarc }) => {
  const items = [
    { label: 'SPF', value: spf },
    { label: 'DKIM', value: dkim },
    { label: 'DMARC', value: dmarc },
  ];
  return (
    <div className="user-auth-row">
      {items.map(({ label, value }) => {
        const status = (value || 'none').toLowerCase();
        const passed = status === 'pass';
        return (
          <div key={label} className={`user-auth-badge ${passed ? 'pass' : status === 'none' ? 'none' : 'fail'}`}>
            <span className="user-auth-dot" />
            <span className="user-auth-label">{label}</span>
            <span className="user-auth-value">{(value || 'N/A').toUpperCase()}</span>
          </div>
        );
      })}
    </div>
  );
};

/* ── Results view ───────────────────────────────────────────────── */
const ResultsView = ({ result, onReset }) => {
  const breakdown = result.breakdown || {};

  const barData = [
    { label: 'NLP Content', key: 'nlp', value: breakdown.nlp || 0, color: '#a78bfa' },
    { label: 'Header Auth', key: 'header', value: breakdown.header || 0, color: '#3b82f6' },
    { label: 'IP Reputation', key: 'ip', value: breakdown.ip || 0, color: '#22d3ee' },
    { label: 'URL Analysis', key: 'url', value: breakdown.url || 0, color: '#f59e0b' },
  ];

  return (
    <div className="user-results" style={{ animation: 'fadeInUp 0.6s ease' }}>
      {/* Risk Score Hero */}
      <div className="user-card user-hero-card">
        <RiskGauge score={result.risk_score || 0} classification={result.classification || 'UNKNOWN'} />
        {result.evidence_level && (
          <div className="user-evidence-level">
            Evidence: <strong>{result.evidence_level}</strong>
          </div>
        )}
        {result.incident_id && (
          <div style={{
            marginTop: '16px',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '6px 14px',
            background: 'rgba(99, 102, 241, 0.12)',
            border: '1px solid rgba(99, 102, 241, 0.25)',
            borderRadius: '999px',
            fontSize: '0.8rem',
            color: '#c7d2fe',
          }}>
            <span>🛡️</span>
            <span>Security Alert Logged: <strong>INC-{String(result.incident_id).padStart(4, '0')}</strong></span>
            <Link to="/soc" style={{ color: '#a5b4fc', fontWeight: 600, textDecoration: 'underline', marginLeft: '4px' }}>
              View in SOC →
            </Link>
          </div>
        )}
      </div>

      {/* Email Summary */}
      <div className="user-card">
        <h3 className="user-card-title">Email Summary</h3>
        <div className="user-meta-grid">
          <span className="user-meta-key">From</span>
          <span className="user-meta-value mono">{result.from || '—'}</span>
          <span className="user-meta-key">Subject</span>
          <span className="user-meta-value">{result.subject || '—'}</span>
          {result.to && (
            <>
              <span className="user-meta-key">To</span>
              <span className="user-meta-value mono">{result.to}</span>
            </>
          )}
        </div>
        {result.body && (
          <div className="user-body-preview">
            {result.body.length > 300 ? result.body.substring(0, 300) + '…' : result.body}
          </div>
        )}
      </div>

      {/* Authentication */}
      <div className="user-card">
        <h3 className="user-card-title">Authentication</h3>
        <AuthBadges spf={result.spf} dkim={result.dkim} dmarc={result.dmarc} />
      </div>

      {/* Score Breakdown */}
      <div className="user-card">
        <h3 className="user-card-title">Score Breakdown</h3>
        <div className="user-breakdown">
          {barData.map(bar => (
            <div key={bar.key} className="user-bar-row">
              <div className="user-bar-header">
                <span className="user-bar-name">{bar.label}</span>
                <span className="user-bar-value" style={{ color: bar.color }}>{bar.value}%</span>
              </div>
              <div className="user-bar-track">
                <div
                  className="user-bar-fill"
                  style={{
                    width: `${bar.value}%`,
                    background: `linear-gradient(90deg, ${bar.color}88, ${bar.color})`,
                  }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Key Findings */}
      {result.reasons && result.reasons.length > 0 && (
        <div className="user-card">
          <h3 className="user-card-title">Key Findings</h3>
          <ul className="user-reasons">
            {result.reasons.map((reason, i) => (
              <li key={i}>
                <span className="user-reason-icon">⚠️</span>
                <span>{reason}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Flagged Terms */}
      {result.flagged_terms && result.flagged_terms.length > 0 && (
        <div className="user-card">
          <h3 className="user-card-title">Flagged Terms</h3>
          <div className="user-flagged-terms">
            {result.flagged_terms.map((term, i) => (
              <span key={i} className="user-flagged-tag">{term}</span>
            ))}
          </div>
        </div>
      )}

      {/* IP Info */}
      {result.geo && (
        <div className="user-card">
          <h3 className="user-card-title">Sender IP Intelligence</h3>
          <div className="user-meta-grid">
            {result.primary_ip && (
              <>
                <span className="user-meta-key">IP</span>
                <span className="user-meta-value mono">{result.primary_ip}</span>
              </>
            )}
            {result.geo.country && (
              <>
                <span className="user-meta-key">Location</span>
                <span className="user-meta-value">{result.geo.city ? `${result.geo.city}, ` : ''}{result.geo.country}</span>
              </>
            )}
            {result.geo.isp && (
              <>
                <span className="user-meta-key">ISP</span>
                <span className="user-meta-value">{result.geo.isp}</span>
              </>
            )}
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="user-actions">
        <button className="user-btn-primary" onClick={onReset}>
          🔍  Scan Another Email
        </button>
        <Link to="/soc" className="user-btn-secondary">
          Open SOC Dashboard →
        </Link>
      </div>
    </div>
  );
};

/* ── Main User Portal ───────────────────────────────────────────── */
const UserPortal = () => {
  const [result, setResult] = useState(null);

  return (
    <div className="user-portal">
      <div className="user-portal-bg" />

      <header className="user-header">
        <div className="user-logo">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ width: '28px', height: '28px' }}>
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <span>ThreatLens</span>
        </div>
        <Link to="/soc" className="user-soc-link">
          SOC Dashboard →
        </Link>
      </header>

      {!result ? (
        <div className="user-upload-section" style={{ animation: 'fadeInUp 0.6s ease' }}>
          <div className="user-hero-text">
            <h1 className="user-title">AI Email Threat Detector</h1>
            <p className="user-subtitle">
              Upload a suspicious <strong>.eml</strong> file and get an instant AI-powered threat analysis
              with phishing detection, header authentication, IP reputation, and URL scanning.
            </p>
          </div>
          <Upload onResult={setResult} />
          <div className="user-features">
            {[
              { icon: '🧠', title: 'NLP Analysis', desc: 'ML-based phishing detection' },
              { icon: '🔐', title: 'Auth Check', desc: 'SPF, DKIM & DMARC validation' },
              { icon: '🌐', title: 'IP Intel', desc: 'Geo & reputation lookup' },
              { icon: '🔗', title: 'URL Scan', desc: 'Malicious link detection' },
            ].map(f => (
              <div key={f.title} className="user-feature-card">
                <div className="user-feature-icon">{f.icon}</div>
                <div className="user-feature-title">{f.title}</div>
                <div className="user-feature-desc">{f.desc}</div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <ResultsView result={result} onReset={() => setResult(null)} />
      )}

      <footer className="user-footer">
        <span>ThreatLens · AI Email Threat Detector</span>
      </footer>
    </div>
  );
};

export default UserPortal;
