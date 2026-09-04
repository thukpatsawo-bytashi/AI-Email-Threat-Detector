import React, { useState, useRef } from 'react';

const SAMPLES = {
  phishing: {
    from_email: 'service-security@paypa1-update.xyz',
    subject: 'URGENT: Your account has been suspended',
    body: 'Dear Customer,\n\nWe detected unauthorized access to your account from an unrecognized IP address. To prevent permanent closure of your account, you must confirm your password and verify your credentials immediately within 24 hours.\n\nClick here immediately to restore access:\nhttp://185.123.45.67/verify-identity/login.php\n\nSincerely,\nAccount Security Team',
    raw_headers: 'From: "PayPal Support" <service-security@paypa1-update.xyz>\nAuthentication-Results: spf=fail dkim=fail dmarc=fail\nReceived-SPF: fail',
  },
  clean: {
    from_email: 'sarah.miller@enterprise-corp.com',
    subject: 'Sprint Retrospective and Planning Agenda',
    body: 'Hi team,\n\nHere is the proposed agenda for our sprint retrospective on Thursday at 2:00 PM. Please review the shared board and add any discussion topics prior to the meeting.\n\nThanks,\nSarah',
    raw_headers: 'From: Sarah Miller <sarah.miller@enterprise-corp.com>\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\nReceived-SPF: pass',
  },
};

export default function Upload({ onResult }) {
  const [activeTab, setActiveTab] = useState('file'); // 'file' | 'text'

  // File upload state
  const [files, setFiles] = useState([]);
  const [dragOver, setDragOver] = useState(false);
  const inputRef = useRef(null);

  // Dynamic text input state
  const [sender, setSender] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [headers, setHeaders] = useState('');
  const [showAdvancedHeaders, setShowAdvancedHeaders] = useState(false);

  // Status
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  function handleFiles(fileList) {
    setError(null);
    if (!fileList || fileList.length === 0) return;
    
    const validFiles = Array.from(fileList).filter(f => f.name.toLowerCase().endsWith('.eml'));
    if (validFiles.length !== fileList.length) {
      setError('Some files were ignored. Only .eml files are supported.');
    }
    if (validFiles.length > 0) {
      setFiles(prev => [...prev, ...validFiles]);
    }
  }

  function handleDrop(e) {
    e.preventDefault();
    setDragOver(false);
    handleFiles(e.dataTransfer.files);
  }

  function handleDragOver(e) {
    e.preventDefault();
    setDragOver(true);
  }

  function handleDragLeave() {
    setDragOver(false);
  }

  function loadSample(type) {
    setError(null);
    const s = SAMPLES[type];
    if (s) {
      setSender(s.from_email);
      setSubject(s.subject);
      setBody(s.body);
      setHeaders(s.raw_headers);
      setActiveTab('text');
    }
  }

  function clearTextForm() {
    setSender('');
    setSubject('');
    setBody('');
    setHeaders('');
    setError(null);
  }

  async function handleAnalyzeFile() {
    if (files.length === 0) return;
    setLoading(true);
    setError(null);
    try {
      const formData = new FormData();
      files.forEach(f => formData.append('files', f));

      let res;
      try {
        res = await fetch('/api/analyze', { method: 'POST', body: formData });
      } catch {
        res = await fetch('http://localhost:8000/api/analyze', { method: 'POST', body: formData });
      }

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || `Server returned error status ${res.status}`);
      }
      onResult(Array.isArray(data) ? data : [data]);
    } catch (err) {
      setError(err.message || 'Analysis failed. Please ensure the backend server is running.');
    } finally {
      setLoading(false);
    }
  }

  async function handleAnalyzeText() {
    if (!body.trim() && !subject.trim()) {
      setError('Please provide email subject or body text to analyze.');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const payload = {
        from_email: sender.trim(),
        subject: subject.trim(),
        body: body.trim(),
        raw_headers: headers.trim(),
      };

      let res;
      try {
        res = await fetch('/api/analyze-text', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
      } catch {
        res = await fetch('http://localhost:8000/api/analyze-text', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
      }

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || `Server returned error status ${res.status}`);
      }
      onResult(Array.isArray(data) ? data : [data]);
    } catch (err) {
      setError(err.message || 'Analysis failed. Please ensure the backend server is running.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="user-upload-wrapper">
      <div className="user-glass-card">
        {/* Dynamic Mode Switcher Tabs */}
        <div style={{
          display: 'flex',
          gap: '8px',
          marginBottom: '24px',
          background: 'rgba(255, 255, 255, 0.03)',
          padding: '4px',
          borderRadius: '12px',
          border: '1px solid var(--panel-border)',
        }}>
          <button
            onClick={() => { setActiveTab('file'); setError(null); }}
            style={{
              flex: 1,
              padding: '10px 16px',
              borderRadius: '8px',
              border: 'none',
              background: activeTab === 'file' ? 'var(--accent-color)' : 'transparent',
              color: activeTab === 'file' ? '#fff' : 'var(--text-secondary)',
              fontWeight: activeTab === 'file' ? 700 : 500,
              fontSize: '0.88rem',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
            }}
          >
            <span>📁</span> Upload .eml File
          </button>
          <button
            onClick={() => { setActiveTab('text'); setError(null); }}
            style={{
              flex: 1,
              padding: '10px 16px',
              borderRadius: '8px',
              border: 'none',
              background: activeTab === 'text' ? 'var(--accent-color)' : 'transparent',
              color: activeTab === 'text' ? '#fff' : 'var(--text-secondary)',
              fontWeight: activeTab === 'text' ? 700 : 500,
              fontSize: '0.88rem',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
            }}
          >
            Direct Text / Paste Email
          </button>
        </div>

        {/* Tab 1: File Upload (.eml) */}
        {activeTab === 'file' && (
          <div>
            <div
              id="drop-zone"
              className={`user-drop-zone${dragOver ? ' drag-over' : ''}`}
              onClick={() => inputRef.current?.click()}
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
            >
              <div className="user-drop-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ width: '48px', height: '48px', color: 'var(--accent-color)' }}>
                  <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48" />
                </svg>
              </div>
              <p className="user-drop-text">
                Drop your <strong>.eml</strong> file here
              </p>
              <p className="user-drop-hint">or click to browse your files</p>
              <input
                ref={inputRef}
                type="file"
                accept=".eml"
                multiple
                style={{ display: 'none' }}
                onChange={(e) => handleFiles(e.target.files)}
              />
            </div>

            {files.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '16px' }}>
                {files.map((f, i) => (
                  <div key={`${f.name}-${i}`} className="user-selected-file">
                    <div className="user-file-icon">📎</div>
                    <div className="user-file-info">
                      <div className="user-file-name">{f.name}</div>
                      <div className="user-file-size">{(f.size / 1024).toFixed(1)} KB</div>
                    </div>
                    <button
                      className="user-file-remove"
                      onClick={(e) => {
                        e.stopPropagation();
                        setFiles(files.filter((_, index) => index !== i));
                      }}
                      aria-label="Remove file"
                    >
                      ✕
                    </button>
                  </div>
                ))}
              </div>
            )}

            <button
              id="analyze-btn"
              className={`user-analyze-btn${loading ? ' loading' : ''}`}
              disabled={files.length === 0 || loading}
              onClick={handleAnalyzeFile}
            >
              {loading ? (
                <>
                  <span className="user-spinner" />
                  Analyzing File…
                </>
              ) : (
                <>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: '18px', height: '18px' }}>
                    <circle cx="11" cy="11" r="8" />
                    <line x1="21" y1="21" x2="16.65" y2="16.65" />
                  </svg>
                  Analyze {files.length > 1 ? `${files.length} Files` : '.eml File'}
                </>
              )}
            </button>
          </div>
        )}

        {/* Tab 2: Dynamic Text / Paste Input */}
        {activeTab === 'text' && (
          <div>
            <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', alignSelf: 'center', marginRight: '4px' }}>
                Quick Fill:
              </span>
              <button
                type="button"
                onClick={() => loadSample('phishing')}
                style={{
                  background: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.25)',
                  color: '#fca5a5',
                  padding: '4px 10px',
                  borderRadius: '6px',
                  fontSize: '0.75rem',
                  cursor: 'pointer',
                  fontWeight: 600,
                }}
              >
                Sample Phishing Email
              </button>
              <button
                type="button"
                onClick={() => loadSample('clean')}
                style={{
                  background: 'rgba(34, 197, 94, 0.1)',
                  border: '1px solid rgba(34, 197, 94, 0.25)',
                  color: '#86efac',
                  padding: '4px 10px',
                  borderRadius: '6px',
                  fontSize: '0.75rem',
                  cursor: 'pointer',
                  fontWeight: 600,
                }}
              >
                🟢 Sample Legitimate Email
              </button>
              <button
                type="button"
                onClick={clearTextForm}
                style={{
                  background: 'transparent',
                  border: '1px solid var(--panel-border)',
                  color: 'var(--text-muted)',
                  padding: '4px 10px',
                  borderRadius: '6px',
                  fontSize: '0.75rem',
                  cursor: 'pointer',
                  marginLeft: 'auto',
                }}
              >
                Clear
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  From / Sender Address
                </label>
                <input
                  type="text"
                  placeholder='e.g. PayPal Security <support@paypa1-update.xyz>'
                  value={sender}
                  onChange={(e) => setSender(e.target.value)}
                  className="search-input"
                  style={{ width: '100%' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Subject Line
                </label>
                <input
                  type="text"
                  placeholder='e.g. URGENT: Your account has been suspended'
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  className="search-input"
                  style={{ width: '100%' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Email Body (Plain Text or HTML)
                </label>
                <textarea
                  placeholder="Paste or type suspicious email text here..."
                  rows={6}
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  className="search-input"
                  style={{
                    width: '100%',
                    resize: 'vertical',
                    fontFamily: 'inherit',
                    lineHeight: 1.5,
                  }}
                />
              </div>

              <div>
                <button
                  type="button"
                  onClick={() => setShowAdvancedHeaders(!showAdvancedHeaders)}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--accent-color)',
                    fontSize: '0.8rem',
                    cursor: 'pointer',
                    padding: 0,
                    fontWeight: 600,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                  }}
                >
                  <span>{showAdvancedHeaders ? '▼' : '►'}</span>
                  {showAdvancedHeaders ? 'Hide Raw Headers' : 'Add Raw Headers / Authentication Results (Optional)'}
                </button>

                {showAdvancedHeaders && (
                  <div style={{ marginTop: '8px' }}>
                    <textarea
                      placeholder={"Authentication-Results: spf=fail dkim=fail dmarc=fail\nReceived: from suspicious.server.xyz (185.123.45.67)"}
                      rows={3}
                      value={headers}
                      onChange={(e) => setHeaders(e.target.value)}
                      className="search-input"
                      style={{
                        width: '100%',
                        fontFamily: "'SF Mono', 'Fira Code', monospace",
                        fontSize: '0.8rem',
                      }}
                    />
                  </div>
                )}
              </div>
            </div>

            <button
              id="analyze-text-btn"
              className={`user-analyze-btn${loading ? ' loading' : ''}`}
              disabled={(!body.trim() && !subject.trim()) || loading}
              onClick={handleAnalyzeText}
              style={{ marginTop: '20px' }}
            >
              {loading ? (
                <>
                  <span className="user-spinner" />
                  Running AI Threat Analysis…
                </>
              ) : (
                <>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: '18px', height: '18px' }}>
                    <circle cx="11" cy="11" r="8" />
                    <line x1="21" y1="21" x2="16.65" y2="16.65" />
                  </svg>
                  Analyze Email Content
                </>
              )}
            </button>
          </div>
        )}

        {error && (
          <div className="user-error" role="alert">
            <span style={{ color: '#ef4444' }}>●</span>
            <span>{error}</span>
          </div>
        )}
      </div>
    </div>
  );
}
