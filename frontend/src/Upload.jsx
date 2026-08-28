import React, { useState, useRef } from 'react'

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
      const formData = new FormData()
      formData.append('file', file)

      let res
      try {
        res = await fetch('/api/analyze', { method: 'POST', body: formData })
      } catch (_netErr) {
        // Fallback to direct localhost URL if Vite proxy is bypassed
        res = await fetch('http://localhost:8000/api/analyze', { method: 'POST', body: formData })
      }

      const data = await res.json()
      if (!res.ok) {
        throw new Error(data.detail || `Server returned error status ${res.status}`)
      }

      onResult(data)
    } catch (err) {
      setError(err.message || 'Analysis failed. Please check that the backend server is running.')
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
