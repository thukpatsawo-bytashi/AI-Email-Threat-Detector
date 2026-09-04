import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import Dashboard from './Dashboard';
import UserPortal from './UserPortal';
import IMAPMonitor from './IMAPMonitor';

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
      path: '/soc/monitor',
      label: 'Live Monitor',
      icon: (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: '18px', marginRight: '12px', flexShrink: 0 }}>
          <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
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
          <Route path="monitor" element={<IMAPMonitor />} />
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
