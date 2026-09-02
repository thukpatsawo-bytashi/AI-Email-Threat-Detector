import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import Dashboard from './Dashboard';
import UserPortal from './UserPortal';

/* ============================================================
   SOC Analyst Layout (sidebar + nested routes under /soc)
   ============================================================ */

const Sidebar = () => {
  const location = useLocation();

  const navItems = [
    {
      path: '/soc',
      label: 'SOC Dashboard',
      icon: (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: '18px', marginRight: '12px', flexShrink: 0 }}>
          <rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
          <line x1="3" y1="9" x2="21" y2="9" />
          <line x1="9" y1="21" x2="9" y2="9" />
        </svg>
      ),
    },
    {
      path: '/soc/reports',
      label: 'Reports',
      icon: (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: '18px', marginRight: '12px', flexShrink: 0 }}>
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
          <polyline points="14 2 14 8 20 8" />
          <line x1="16" y1="13" x2="8" y2="13" />
          <line x1="16" y1="17" x2="8" y2="17" />
        </svg>
      ),
    },
    {
      path: '/soc/settings',
      label: 'Settings',
      icon: (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: '18px', marginRight: '12px', flexShrink: 0 }}>
          <circle cx="12" cy="12" r="3" />
          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
        </svg>
      ),
    },
  ];

  return (
    <div className="sidebar">
      <Link to="/" className="sidebar-title" style={{ textDecoration: 'none' }}>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ width: '22px', height: '22px', marginRight: '10px', flexShrink: 0 }}>
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
        ThreatLens
      </Link>

      <nav style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
        {navItems.map(item => (
          <Link
            key={item.path}
            to={item.path}
            className={`nav-link ${location.pathname === item.path ? 'active' : ''}`}
          >
            {item.icon}
            {item.label}
          </Link>
        ))}

        <div style={{
          marginTop: '16px',
          paddingTop: '16px',
          borderTop: '1px solid var(--panel-border)',
        }}>
          <Link to="/" className={`nav-link`} style={{ color: 'var(--accent-color)' }}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: '18px', marginRight: '12px', flexShrink: 0 }}>
              <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48" />
            </svg>
            Scan Email
          </Link>
        </div>
      </nav>

      <div style={{
        marginTop: 'auto',
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        padding: '16px',
        background: 'rgba(255, 255, 255, 0.03)',
        borderRadius: 'var(--radius-md)',
        border: '1px solid var(--panel-border)',
      }}>
        <div style={{
          width: '36px',
          height: '36px',
          borderRadius: '50%',
          background: 'linear-gradient(135deg, #6366f1, #a78bfa)',
          flexShrink: 0,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: '0.9rem',
          fontWeight: 700,
          color: 'white',
        }}>
          SA
        </div>
        <div>
          <div style={{ fontWeight: 600, fontSize: '0.85rem' }}>SOC Analyst</div>
          <div style={{
            fontSize: '0.72rem',
            color: '#86efac',
            display: 'flex',
            alignItems: 'center',
            gap: '4px',
          }}>
            <span style={{
              width: '6px',
              height: '6px',
              borderRadius: '50%',
              background: '#22c55e',
              display: 'inline-block',
            }} />
            Online
          </div>
        </div>
      </div>
    </div>
  );
};

const SOCLayout = () => {
  return (
    <div className="app-container">
      <Sidebar />
      <main className="main-content">
        <Routes>
          <Route index element={<Dashboard />} />
          <Route
            path="reports"
            element={
              <div style={{ animation: 'fadeIn 0.5s ease' }}>
                <div className="glass-panel" style={{ textAlign: 'center', padding: '80px 40px' }}>
                  <div style={{ fontSize: '3rem', marginBottom: '16px' }}>📊</div>
                  <h2 className="dashboard-title" style={{ marginBottom: '12px' }}>Reports</h2>
                  <p style={{ color: 'var(--text-secondary)', maxWidth: '400px', margin: '0 auto', lineHeight: 1.7 }}>
                    Automated threat reports and executive summaries are coming soon.
                  </p>
                </div>
              </div>
            }
          />
          <Route
            path="settings"
            element={
              <div style={{ animation: 'fadeIn 0.5s ease' }}>
                <div className="glass-panel" style={{ textAlign: 'center', padding: '80px 40px' }}>
                  <div style={{ fontSize: '3rem', marginBottom: '16px' }}>⚙️</div>
                  <h2 className="dashboard-title" style={{ marginBottom: '12px' }}>Settings</h2>
                  <p style={{ color: 'var(--text-secondary)', maxWidth: '400px', margin: '0 auto', lineHeight: 1.7 }}>
                    Configure alert thresholds, integrations, and notification preferences.
                  </p>
                </div>
              </div>
            }
          />
        </Routes>
      </main>
    </div>
  );
};

/* ============================================================
   Root App – Route split between User Portal and SOC Dashboard
   ============================================================ */

const App = () => {
  return (
    <Router>
      <Routes>
        {/* User-facing email scanner */}
        <Route path="/" element={<UserPortal />} />

        {/* SOC Analyst dashboard (with sidebar layout) */}
        <Route path="/soc/*" element={<SOCLayout />} />
      </Routes>
    </Router>
  );
};

export default App;
