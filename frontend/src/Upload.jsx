import React, { useState, useRef } from 'react'

/* ──────────────────────────────────────────────────────────────
   MOCK RESPONSE — swap for real fetch at integration time
   ────────────────────────────────────────────────────────────── */
const MOCK_RESULT = {
  from: "billing@company-payments.xyz",
  subject: "URGENT: Outstanding Invoice",
  body: "Your account will be suspended...",
  received_chain: ["Received: from suspicious-server...", "Received: by another-mail-server..."],
  spf: "fail",
  dkim: "fail",
  dmarc: "fail",
  sender_reply_mismatch: true,
  domain_lookalike: false,
  domain_age_days: null,
  anomalies: ["Sender identity mismatch", "Multiple authentication failures"],
  header_risk_score: 80,
  extracted_ips: ["185.123.45.67"],
  primary_ip: "185.123.45.67",
  geo: { country: "Germany", city: "Frankfurt", isp: "Example Hosting Provider" },
  ip_risk_score: 60,
  phishing_probability: 91,
  legitimate_probability: 3,
  flagged_terms: ["urgent", "account suspended", "click immediately"],
  method: "heuristic",
  risk_score: 89,
  classification: "CRITICAL",
  reasons: [
    "SPF failed",
    "DKIM failed",
    "Sender/Reply-To mismatch",
    "High phishing probability (91%)",
  ],
  breakdown: { nlp: 91, header: 80, ip: 60 },
}

async function mockAnalyze(_file) {
  // Simulate network latency
  await new Promise((r) => setTimeout(r, 1200))
  return MOCK_RESULT
}

/* ──────────────────────────────────────────────────────────────
   Upload Component
   ────────────────────────────────────────────────────────────── */
export default function Upload({ onResult }) {
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [dragOver, setDragOver] = useState(false)
  const inputRef = useRef(null)

  function handleFile(f) {
    setError(null)
    if (!f) return
    if (!f.name.toLowerCase().endsWith('.eml')) {
      setError('Only .eml files are supported.')
      return
    }
    setFile(f)
  }

  function handleDrop(e) {
    e.preventDefault()
    setDragOver(false)
    const f = e.dataTransfer.files?.[0]
    handleFile(f)
  }

  function handleDragOver(e) {
    e.preventDefault()
    setDragOver(true)
  }

  function handleDragLeave() {
    setDragOver(false)
  }

  function handleInputChange(e) {
    handleFile(e.target.files?.[0])
  }

  async function handleAnalyze() {
    if (!file) return
    setLoading(true)
    setError(null)
    try {
      // ── STUB: swap for real fetch at integration ────────────
      // const formData = new FormData()
      // formData.append('file', file)
      // const res = await fetch('/api/analyze', { method: 'POST', body: formData })
      // const data = await res.json()
      // if (!res.ok) throw new Error(data.detail || res.statusText)

      const data = await mockAnalyze(file)
      onResult(data)
    } catch (err) {
      setError(err.message || 'Analysis failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="upload-section">
      <div className="glass-card">
        <div
          id="drop-zone"
          className={`drop-zone${dragOver ? ' drag-over' : ''}`}
          onClick={() => inputRef.current?.click()}
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
        >
          <span className="drop-zone-icon">📧</span>
          <p className="drop-zone-text">
            Drop your <strong>.eml</strong> file here, or click to browse
          </p>
          <p className="drop-zone-hint">Supports standard .eml email files</p>
          <input
            ref={inputRef}
            type="file"
            accept=".eml"
            className="file-input"
            onChange={handleInputChange}
          />
        </div>

        {file && (
          <div className="selected-file">
            <span className="selected-file-icon">📎</span>
            <span className="selected-file-name">{file.name}</span>
            <button
              className="selected-file-remove"
              onClick={() => setFile(null)}
              aria-label="Remove file"
            >
              ✕
            </button>
          </div>
        )}

        <button
          id="analyze-btn"
          className={`analyze-btn${loading ? ' loading' : ''}`}
          disabled={!file || loading}
          onClick={handleAnalyze}
        >
          {loading ? (
            <>
              <span className="spinner" />
              Analyzing…
            </>
          ) : (
            '🔍  Analyze Email'
          )}
        </button>

        {error && (
          <div className="error-banner" role="alert">
            <span>⚠️</span>
            <span>{error}</span>
          </div>
        )}
      </div>
    </div>
  )
}
