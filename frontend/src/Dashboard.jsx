import React from 'react'

/* ──────────────────────────────────────────────────────────────
   Helpers
   ────────────────────────────────────────────────────────────── */
const RISK_COLORS = {
  LOW: 'var(--risk-low)',
  MEDIUM: 'var(--risk-medium)',
  HIGH: 'var(--risk-high)',
  CRITICAL: 'var(--risk-critical)',
}

function riskColor(classification) {
  return RISK_COLORS[classification] || RISK_COLORS.MEDIUM
}

/* ──────────────────────────────────────────────────────────────
   Sub-components
   ────────────────────────────────────────────────────────────── */
function RiskHero({ risk_score, classification }) {
  const color = riskColor(classification)
  return (
    <div className="glass-card risk-hero" style={{ '--ring-glow': color }}>
      <div className="risk-score-ring">
        <div>
          <div className="risk-score-number" style={{ color }}>
            {risk_score}
          </div>
          <div className="risk-score-label">Risk Score</div>
        </div>
      </div>
      <span className={`risk-badge ${classification}`}>
        {classification === 'CRITICAL' && '🚨 '}
        {classification === 'HIGH' && '⚠️ '}
        {classification === 'MEDIUM' && '⚡ '}
        {classification === 'LOW' && '✅ '}
        {classification}
      </span>
    </div>
  )
}

function AuthBadges({ spf, dkim, dmarc }) {
  const items = [
    { label: 'SPF', value: spf },
    { label: 'DKIM', value: dkim },
    { label: 'DMARC', value: dmarc },
  ]
  return (
    <div className="auth-badges">
      {items.map((item) => (
        <span key={item.label} className={`auth-badge ${item.value}`}>
          {item.value === 'pass' ? '✓' : item.value === 'fail' ? '✗' : '—'}{' '}
          {item.label}
        </span>
      ))}
    </div>
  )
}

function ReasonsCard({ reasons }) {
  return (
    <div className="glass-card">
      <h2 className="section-title">Threat Indicators</h2>
      <ul className="reasons-list">
        {reasons.map((r, i) => (
          <li key={i}>
            <span className="reason-dot" />
            {r}
          </li>
        ))}
      </ul>
    </div>
  )
}

function BreakdownCard({ breakdown, riskMetrics, evidenceLevel }) {
  const bars = [
    { key: 'nlp', label: 'NLP / Content Analysis', cls: 'nlp' },
    { key: 'header', label: 'Header Authentication', cls: 'header' },
    { key: 'ip', label: 'IP Reputation', cls: 'ip' },
  ]
  if (typeof breakdown.url === 'number') {
    bars.push({ key: 'url', label: 'URL Analysis', cls: 'url' })
  }

  const metricBars = riskMetrics ? [
    { key: 'content', label: 'Content Evidence', cls: 'nlp' },
    { key: 'authentication', label: 'Authentication Proof', cls: 'header' },
    { key: 'identity', label: 'Sender Identity', cls: 'header' },
    { key: 'domain', label: 'Domain Signals', cls: 'ip' },
    { key: 'network', label: 'Network Reputation', cls: 'ip' },
    { key: 'url', label: 'URL Evidence', cls: 'url' },
  ] : []

  return (
    <div className="glass-card">
      <h2 className="section-title">Risk Breakdown</h2>
      <div className="breakdown-bars">
        {bars.map(({ key, label, cls }) => (
          <div className="bar-row" key={key}>
            <div className="bar-label">
              <span className="bar-label-name">{label}</span>
              <span className="bar-label-value" style={{ color: `var(--bar-${cls})` }}>
                {breakdown[key]}%
              </span>
            </div>
            <div className="bar-track">
              <div
                className={`bar-fill ${cls}`}
                style={{ width: `${breakdown[key]}%` }}
              />
            </div>
          </div>
        ))}
      </div>

      {riskMetrics && (
        <div className="evidence-panel">
          <div className="evidence-summary">
            <span>Evidence Level</span>
            <strong>{evidenceLevel}</strong>
          </div>
          <div className="evidence-summary">
            <span>Analysis Confidence</span>
            <strong>{riskMetrics.analysis_confidence}%</strong>
          </div>
          <div className="evidence-tags">
            {(riskMetrics.evidence_sources?.length ? riskMetrics.evidence_sources : ['no strong evidence']).map((source) => (
              <span key={source} className="evidence-tag">
                {source}
              </span>
            ))}
          </div>
          <div className="breakdown-bars compact-bars">
            {metricBars.map(({ key, label, cls }) => (
              <div className="bar-row" key={key}>
                <div className="bar-label">
                  <span className="bar-label-name">{label}</span>
                  <span className="bar-label-value" style={{ color: `var(--bar-${cls})` }}>
                    {riskMetrics[key] ?? 0}
                  </span>
                </div>
                <div className="bar-track">
                  <div
                    className={`bar-fill ${cls}`}
                    style={{ width: `${Math.min(100, riskMetrics[key] ?? 0)}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function SenderCard({ primary_ip, geo, flagged_terms }) {
  return (
    <div className="glass-card">
      <h2 className="section-title">Sender Intelligence</h2>
      <div className="sender-info">
        <div className="sender-row">
          <span className="sender-key">Primary IP</span>
          <span className="sender-value">{primary_ip || '—'}</span>
        </div>
        {geo && (
          <>
            <div className="sender-row">
              <span className="sender-key">Location</span>
              <span className="sender-value">
                {geo.city}, {geo.country}
              </span>
            </div>
            <div className="sender-row">
              <span className="sender-key">ISP</span>
              <span className="sender-value">{geo.isp}</span>
            </div>
          </>
        )}
        <div className="sender-disclaimer">
          ⚠️ Approximate network location based on IP geolocation — not proof of
          sender origin. Received headers can be forged.
        </div>
      </div>

      {flagged_terms?.length > 0 && (
        <>
          <h2 className="section-title" style={{ marginTop: 20 }}>
            Flagged Terms
          </h2>
          <div className="flagged-terms">
            {flagged_terms.map((t) => (
              <span key={t} className="flagged-term">
                "{t}"
              </span>
            ))}
          </div>
        </>
      )}
    </div>
  )
}

function EmailSummaryCard({ from, subject, body, spf, dkim, dmarc }) {
  return (
    <div className="glass-card">
      <h2 className="section-title">Email Summary</h2>
      <AuthBadges spf={spf} dkim={dkim} dmarc={dmarc} />
      <div className="email-meta">
        <div className="email-meta-row">
          <span className="email-meta-key">From</span>
          <span className="email-meta-value">{from}</span>
        </div>
        <div className="email-meta-row">
          <span className="email-meta-key">Subject</span>
          <span className="email-meta-value">{subject}</span>
        </div>
        <div className="email-body-preview">{body}</div>
      </div>
    </div>
  )
}

/* ──────────────────────────────────────────────────────────────
   Dashboard
   ────────────────────────────────────────────────────────────── */
export default function Dashboard({ result, onReset }) {
  if (!result) return null

  const {
    risk_score = 0,
    classification = 'MEDIUM',
    reasons = [],
    breakdown = { nlp: 0, header: 0, ip: 0 },
    risk_metrics = null,
    evidence_level = 'LOW',
    from: senderFrom = '',
    subject = '',
    body = '',
    spf = 'none',
    dkim = 'none',
    dmarc = 'none',
    primary_ip = '',
    geo = null,
    flagged_terms = [],
  } = result

  return (
    <div className="dashboard">
      <div className="dashboard-grid">
        <RiskHero risk_score={risk_score} classification={classification} />

        <div className="dashboard-cols">
          <ReasonsCard reasons={reasons} />
          <BreakdownCard
            breakdown={breakdown}
            riskMetrics={risk_metrics}
            evidenceLevel={evidence_level}
          />
        </div>

        <div className="dashboard-cols">
          <SenderCard
            primary_ip={primary_ip}
            geo={geo}
            flagged_terms={flagged_terms}
          />
          <EmailSummaryCard
            from={senderFrom}
            subject={subject}
            body={body}
            spf={spf}
            dkim={dkim}
            dmarc={dmarc}
          />
        </div>
      </div>

      <button className="new-scan-btn" onClick={onReset}>
        ← Scan Another Email
      </button>
    </div>
  )
}
