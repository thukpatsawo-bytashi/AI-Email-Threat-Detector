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
        Dashboard
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
