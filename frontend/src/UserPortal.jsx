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
const ResultsView = ({ result, onReset, hideActions }) => {
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
            background: 'rgba(34, 197, 94, 0.1)',
            border: '1px solid rgba(34, 197, 94, 0.2)',
            borderRadius: '999px',
            fontSize: '0.8rem',
            color: '#86efac',
          }}>
            <span>Alert</span>
            <span>Security Alert Logged: <strong>INC-{String(result.incident_id).padStart(4, '0')}</strong></span>
            <Link to="/soc" style={{ color: '#86efac', fontWeight: 600, textDecoration: 'underline', marginLeft: '4px' }}>
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
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {result.reasons.map((reason, idx) => {
              const isDict = typeof reason === 'object' && reason !== null;
              const severity = isDict ? (reason.severity || 'LOW') : 'MEDIUM';
              const message = isDict ? (reason.message || '') : reason;
              const category = isDict ? (reason.category || 'General') : 'General';
              
              const sevColor = severity === 'CRITICAL' ? '#ef4444' :
                               severity === 'HIGH' ? '#f97316' :
                               severity === 'MEDIUM' ? '#eab308' : '#22c55e';
                               
              return (
                <div key={idx} style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '12px',
                  padding: '10px 14px',
                  background: `${sevColor}10`,
                  borderLeft: `3px solid ${sevColor}`,
                  borderRadius: '0 6px 6px 0',
                  fontSize: '0.85rem'
                }}>
                  <span style={{
                    fontSize: '0.65rem',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    padding: '2px 6px',
                    background: `${sevColor}25`,
                    color: sevColor,
                    borderRadius: '4px',
                    letterSpacing: '0.5px',
                    marginTop: '2px',
                    minWidth: '55px',
                    textAlign: 'center'
                  }}>
                    {category}
                  </span>
                  <span style={{ color: 'var(--text-primary)', lineHeight: '1.4' }}>
                    {message}
                  </span>
                </div>
              );
            })}
          </div>
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

      {/* Sender IP Intelligence Card */}
      {result.geo && (
        <div className="user-card" style={{ padding: '24px', background: 'rgba(30, 41, 59, 0.4)', border: '1px solid rgba(255,255,255,0.1)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '20px', flexWrap: 'wrap', gap: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <h3 className="user-card-title" style={{ margin: 0, borderBottom: 'none', paddingBottom: 0 }}>Sender IP Intelligence</h3>
            </div>
            
            {result.ip_risk_score !== undefined && (
              <span className={`user-risk-badge ${result.ip_risk_score >= 80 ? 'critical' : result.ip_risk_score >= 60 ? 'high' : result.ip_risk_score >= 30 ? 'medium' : 'low'}`} style={{ fontSize: '0.75rem', padding: '6px 12px' }}>
                Risk Score: {result.ip_risk_score}/100
              </span>
            )}
          </div>
          
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '20px', background: 'rgba(15, 23, 42, 0.5)', padding: '20px', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.05)' }}>
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>Origin IP</div>
              <div style={{ fontSize: '1.25rem', fontFamily: 'monospace', fontWeight: 700, color: '#e2e8f0' }}>{result.primary_ip || 'Unknown'}</div>
              
              {result.reputation && result.reputation.reputation_available && (
                <div style={{ marginTop: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <div style={{ 
                    width: '8px', 
                    height: '8px', 
                    borderRadius: '50%', 
                    background: result.reputation.abuse_confidence_score > 0 ? '#ef4444' : '#22c55e',
                    boxShadow: `0 0 8px ${result.reputation.abuse_confidence_score > 0 ? '#ef4444' : '#22c55e'}`
                  }} />
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    AbuseIPDB Score: <strong style={{ color: result.reputation.abuse_confidence_score > 0 ? '#fca5a5' : '#86efac' }}>{result.reputation.abuse_confidence_score}%</strong>
                  </span>
                </div>
              )}
            </div>
            
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>Location</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '1.05rem', color: '#f8fafc', fontWeight: 500 }}>
                <span style={{ color: 'var(--accent-color)' }}>●</span>
                {result.geo.city && result.geo.city !== 'Unknown' ? `${result.geo.city}, ` : ''}{result.geo.country || 'Unknown'}
              </div>
            </div>
            
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>ISP / Network</div>
              <div style={{ fontSize: '1.05rem', color: '#f8fafc', fontWeight: 500 }}>{result.geo.isp || 'Unknown'}</div>
            </div>
          </div>

          {/* VPN/Proxy Warnings */}
          {(result.geo.proxy || result.geo.hosting) && (
            <div style={{ marginTop: '20px', padding: '16px', background: 'rgba(239, 68, 68, 0.08)', borderLeft: '4px solid #ef4444', borderRadius: '4px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#fca5a5', fontWeight: 700, fontSize: '0.95rem' }}>
                <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" strokeWidth="2.5" fill="none" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                <span>Anonymization Service Detected</span>
              </div>
              <p style={{ margin: '8px 0 0 30px', fontSize: '0.85rem', color: 'rgba(255,255,255,0.8)', lineHeight: 1.5 }}>
                This IP belongs to a <strong>{result.geo.proxy ? 'VPN or Proxy service' : ''}{result.geo.proxy && result.geo.hosting ? ' and ' : ''}{result.geo.hosting ? 'Datacenter / Cloud Hosting provider' : ''}</strong>. 
                Attackers commonly use these services to mask their true location and bypass geographical restrictions.
              </p>
            </div>
          )}
        </div>
      )}

      {/* URL Analysis */}
      {result.urls && result.urls.length > 0 && (
        <div className="user-card" style={{ padding: '24px', background: 'rgba(30, 41, 59, 0.4)', border: '1px solid rgba(255,255,255,0.1)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h3 className="user-card-title" style={{ margin: 0, borderBottom: 'none', paddingBottom: 0 }}>URL Analysis</h3>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              {result.urls.length} URL{result.urls.length !== 1 ? 's' : ''} detected
            </span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {result.urls.map((url, i) => {
              const urlClassColor = url.classification === 'MALICIOUS' ? '#ef4444' :
                url.classification === 'SUSPICIOUS' ? '#f97316' : '#22c55e';
              return (
                <div key={i} style={{
                  padding: '14px',
                  background: 'rgba(15, 23, 42, 0.5)',
                  border: `1px solid ${urlClassColor}22`,
                  borderLeft: `3px solid ${urlClassColor}`,
                  borderRadius: '8px',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <span style={{
                      fontFamily: "'SF Mono', 'Fira Code', monospace",
                      fontSize: '0.8rem',
                      color: '#e2e8f0',
                      wordBreak: 'break-all',
                      maxWidth: '75%',
                    }}>
                      {url.original_url || url.normalized_url || 'Unknown URL'}
                    </span>
                    <span style={{
                      fontSize: '0.7rem',
                      padding: '3px 10px',
                      borderRadius: '999px',
                      fontWeight: 700,
                      background: `${urlClassColor}18`,
                      color: urlClassColor,
                      border: `1px solid ${urlClassColor}33`,
                    }}>
                      {url.classification} ({url.risk_score || 0})
                    </span>
                  </div>
                  {url.hostname && (
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '6px' }}>
                      Host: <span style={{ color: 'var(--text-secondary)' }}>{url.hostname}</span>
                      {url.registrable_domain && url.registrable_domain !== url.hostname && (
                        <> · Domain: <span style={{ color: 'var(--text-secondary)' }}>{url.registrable_domain}</span></>
                      )}
                    </div>
                  )}
                  {url.detections && url.detections.length > 0 && (
                    <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      {url.detections.slice(0, 3).map((d, j) => (
                        <div key={j} style={{ fontSize: '0.73rem', color: 'var(--text-secondary)', display: 'flex', gap: '6px' }}>
                          <span style={{
                            fontSize: '0.65rem',
                            padding: '1px 6px',
                            borderRadius: '4px',
                            fontWeight: 700,
                            background: d.strength === 'strong' ? 'rgba(239,68,68,0.15)' :
                              d.strength === 'moderate' ? 'rgba(249,115,22,0.15)' : 'rgba(234,179,8,0.15)',
                            color: d.strength === 'strong' ? '#fca5a5' :
                              d.strength === 'moderate' ? '#fdba74' : '#fde047',
                            flexShrink: 0,
                          }}>
                            {(d.strength || '').toUpperCase()}
                          </span>
                          <span>{d.explanation || d.signal}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Actions */}
      {!hideActions && (
        <div className="user-actions">
          <button className="user-btn-primary" onClick={onReset}>
            Scan Another Email
          </button>
          <button
            className="user-btn-secondary"
            onClick={() => {
              const id = result.incident_id || result.numeric_id || result.email_id;
              if (id) {
                window.open(`/api/incidents/${id}/report`, '_blank');
              }
            }}
            style={{ display: result.incident_id || result.numeric_id || result.email_id ? undefined : 'none' }}
          >
            Download Report
          </button>
          <Link to="/soc" className="user-btn-secondary">
            Open SOC Dashboard →
          </Link>
        </div>
      )}
    </div>
  );
};

/* ── Multi-Result View ─────────────────────────────────────────────── */
const MultiResultsView = ({ results, onReset }) => {
  const [expandedIndex, setExpandedIndex] = useState(results.length === 1 ? 0 : null);

  return (
    <div className="user-multi-results" style={{ animation: 'fadeInUp 0.6s ease', width: '100%', maxWidth: '800px', margin: '0 auto', padding: '0 20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Analysis Results</h2>
          <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Processed {results.length} {results.length === 1 ? 'file' : 'files'}
          </div>
        </div>
        <div style={{ display: 'flex', gap: '12px' }}>
          <button className="user-btn-primary" onClick={onReset} style={{ padding: '10px 18px', fontSize: '0.85rem' }}>
            Scan More
          </button>
          <Link to="/soc" className="user-btn-secondary" style={{ padding: '10px 18px', fontSize: '0.85rem' }}>
            SOC Dashboard →
          </Link>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', paddingBottom: '40px' }}>
        {results.map((result, i) => (
          <div key={i} style={{
            background: 'rgba(30, 41, 59, 0.5)',
            border: '1px solid var(--panel-border)',
            borderRadius: '12px',
            overflow: 'hidden',
          }}>
            {/* Summary Header */}
            <div 
              onClick={() => setExpandedIndex(expandedIndex === i ? null : i)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '16px 20px',
                cursor: 'pointer',
                background: expandedIndex === i ? 'rgba(255,255,255,0.03)' : 'transparent',
                transition: 'background 0.2s ease',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flex: 1, overflow: 'hidden' }}>
                <div style={{ 
                  width: '42px', 
                  height: '42px', 
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontWeight: 700,
                  fontSize: '0.95rem',
                  background: result.risk_score >= 80 ? 'rgba(239, 68, 68, 0.15)' : result.risk_score >= 60 ? 'rgba(249, 115, 22, 0.15)' : result.risk_score >= 30 ? 'rgba(234, 179, 8, 0.15)' : 'rgba(34, 197, 94, 0.15)',
                  color: result.risk_score >= 80 ? '#ef4444' : result.risk_score >= 60 ? '#f97316' : result.risk_score >= 30 ? '#eab308' : '#22c55e',
                  border: `2px solid ${result.risk_score >= 80 ? '#ef4444' : result.risk_score >= 60 ? '#f97316' : result.risk_score >= 30 ? '#eab308' : '#22c55e'}`,
                  flexShrink: 0,
                }}>
                  {result.risk_score}
                </div>
                <div style={{ flex: 1, minWidth: 0, paddingRight: '12px' }}>
                  <div style={{ 
                    fontWeight: 600, 
                    fontSize: '1rem', 
                    color: 'var(--text-primary)', 
                    whiteSpace: 'nowrap', 
                    overflow: 'hidden', 
                    textOverflow: 'ellipsis' 
                  }}>
                    {result.subject || 'No Subject'}
                  </div>
                  <div style={{ 
                    fontSize: '0.8rem', 
                    color: 'var(--text-secondary)',
                    whiteSpace: 'nowrap', 
                    overflow: 'hidden', 
                    textOverflow: 'ellipsis' 
                  }}>
                    From: {result.from || 'Unknown'}
                  </div>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexShrink: 0 }}>
                <span className={`user-risk-badge ${(result.classification || 'UNKNOWN').toLowerCase()}`} style={{ fontSize: '0.75rem', padding: '4px 10px', margin: 0 }}>
                  {result.classification}
                </span>
                <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" style={{ 
                  color: 'var(--text-muted)',
                  transform: expandedIndex === i ? 'rotate(180deg)' : 'rotate(0deg)',
                  transition: 'transform 0.3s ease'
                }}>
                  <polyline points="6 9 12 15 18 9"></polyline>
                </svg>
              </div>
            </div>

            {/* Expanded Content */}
            {expandedIndex === i && (
              <div style={{ padding: '24px 20px', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                <ResultsView result={result} hideActions={true} />
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

/* ── Main User Portal ───────────────────────────────────────────── */
const UserPortal = () => {
  const [results, setResults] = useState(null);

  return (
    <div className="user-portal">
      <div className="user-portal-bg" />

      <header className="user-header">
        <div className="user-logo">
          {/* Logo removed */}
        </div>
        <Link to="/soc" className="user-soc-link">
          SOC Dashboard →
        </Link>
      </header>

      {!results || results.length === 0 ? (
        <div className="user-upload-section" style={{ animation: 'fadeInUp 0.6s ease' }}>
          <div className="user-hero-text">
            <h1 className="user-title">Email Analysis</h1>
            <p className="user-subtitle">
              Upload <strong>.eml</strong> files for comprehensive analysis
              including content inspection, header authentication, IP reputation, and URL scanning.
            </p>
          </div>
          <Upload onResult={setResults} />
          <div className="user-features">
            {[
              { icon: 'NLP', title: 'Content Analysis', desc: 'Phishing pattern detection' },
              { icon: 'AUTH', title: 'Auth Check', desc: 'SPF, DKIM & DMARC validation' },
              { icon: 'IP', title: 'IP Intel', desc: 'Geo & reputation lookup' },
              { icon: 'URL', title: 'URL Scan', desc: 'Malicious link detection' },
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
        <MultiResultsView results={results} onReset={() => setResults(null)} />
      )}

      <footer className="user-footer">
        <span></span>
      </footer>
    </div>
  );
};

export default UserPortal;
