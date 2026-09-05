import { useState, useEffect } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import { getHosts } from '../api/client';

export default function Layout() {
  const [stats, setStats] = useState({});
  const [sidebarOpen, setSidebarOpen] = useState(false);

  useEffect(() => {
    getHosts()
      .then((hosts) => {
        const sorted = [...hosts].sort((a, b) => (b.aggregate_risk_score || 0) - (a.aggregate_risk_score || 0));
        const totalHosts = sorted.length;
        const totalSessions = sorted.reduce((s, h) => s + (h.session_count || 0), 0);
        const criticalHosts = sorted.filter((h) => (h.aggregate_risk_score || 0) >= 75).length;
        setStats({ totalHosts, totalSessions, criticalHosts });
      })
      .catch(() => setStats({ totalHosts: 0, totalSessions: 0, criticalHosts: 0 }));
  }, []);

  return (
    <div className="app-layout">
      <Sidebar stats={stats} isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />
      <div className="app-main">
        <header className="app-header">
          <div className="flex items-center gap-md">
            <button className="mobile-menu-toggle" onClick={() => setSidebarOpen(!sidebarOpen)}>
              ☰
            </button>
            <div>
              <div className="flex items-center gap-sm">
                <span style={{ fontWeight: 700, fontSize: 'var(--font-size-base)' }}>Secure SMTP</span>
                <span className="badge badge-info" style={{ fontSize: '0.6rem' }}>ENTERPRISE AUDIT</span>
              </div>
            </div>
          </div>
          <div className="status-beacon">
            <span className="status-dot status-dot-active" />
            <span style={{ color: 'var(--sage-clear)' }}>
              ENGINE READY ({stats.totalHosts ?? 0} HOSTS / {stats.totalSessions ?? 0} SESSIONS)
            </span>
          </div>
        </header>
        <main className="app-content">
          <Outlet />
        </main>
        <footer className="app-footer">
          <span>Secure SMTP &bull; Cryptographic Posture Intelligence</span>
          <span className="app-footer-attribution">
            Project belongs to{' '}
            <a
              href="https://github.com/sharmaharshit1661-web"
              target="_blank"
              rel="noopener noreferrer"
              className="app-footer-link"
            >
              @sharmaharshit1661-web
            </a>
          </span>
        </footer>
      </div>
    </div>
  );
}
