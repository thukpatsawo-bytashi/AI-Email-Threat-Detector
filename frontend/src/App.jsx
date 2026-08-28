import React, { useState } from 'react'
import Upload from './Upload'
import Dashboard from './Dashboard'

// Demo data for ?demo mode (visual testing only)
const DEMO_DATA = {
  from: "billing@company-payments.xyz",
  subject: "URGENT: Outstanding Invoice",
  body: "Your account will be suspended...",
  received_chain: ["Received: from suspicious-server...", "Received: by another-mail-server..."],
  spf: "fail", dkim: "fail", dmarc: "fail",
  sender_reply_mismatch: true, domain_lookalike: false, domain_age_days: null,
  anomalies: ["Sender identity mismatch", "Multiple authentication failures"],
  header_risk_score: 80,
  extracted_ips: ["185.123.45.67"], primary_ip: "185.123.45.67",
  geo: { country: "Germany", city: "Frankfurt", isp: "Example Hosting Provider" },
  ip_risk_score: 60,
  phishing_probability: 91, legitimate_probability: 3,
  flagged_terms: ["urgent", "account suspended", "click immediately"],
  method: "heuristic",
  risk_score: 89, classification: "CRITICAL",
  reasons: ["SPF failed", "DKIM failed", "Sender/Reply-To mismatch", "High phishing probability (91%)"],
  breakdown: { nlp: 91, header: 80, ip: 60 },
}

export default function App() {
  const isDemo = typeof window !== 'undefined' && new URLSearchParams(window.location.search).has('demo')
  const [result, setResult] = useState(isDemo ? DEMO_DATA : null)

  return (
    <div className="app">
      <header className="app-header">
        <h1 className="app-logo">🛡️ AI Email Threat Detector</h1>
        <p className="app-tagline">
          Upload a suspicious email and get an instant threat analysis
        </p>
      </header>

      {!result ? (
        <Upload onResult={setResult} />
      ) : (
        <Dashboard result={result} onReset={() => setResult(null)} />
      )}
    </div>
  )
}
