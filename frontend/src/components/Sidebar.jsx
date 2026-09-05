import { NavLink } from 'react-router-dom';

const NAV_ITEMS = [
  { to: '/', label: 'Fleet Overview', icon: '🌐' },
  { to: '/sessions', label: 'Session Explorer', icon: '🔬' },
  { to: '/ingest', label: 'Live Ingest', icon: '⚡' },
  { to: '/rules', label: 'Rules & Compliance', icon: '📋' },
];

export default function Sidebar({ stats = {}, isOpen, onClose }) {
  return (
    <aside className={`app-sidebar ${isOpen ? 'open' : ''}`}>
      {/* Brand */}
      <div className="sidebar-brand">
        <div className="sidebar-logo">🛡️</div>
        <div>
          <div className="sidebar-title">Secure SMTP</div>
          <div className="sidebar-subtitle">Cryptographic Ops</div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        <div className="sidebar-section-label">Console</div>
        {NAV_ITEMS.map(({ to, label, icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
            onClick={onClose}
          >
            <span className="sidebar-link-icon">{icon}</span>
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      {/* Live Telemetry Widget */}
      <div className="sidebar-telemetry">
        <div className="sidebar-telemetry-header">
          <span>Live Telemetry</span>
          <div className="status-beacon">
            <span className="status-dot status-dot-active" />
            <span style={{ color: 'var(--sage-clear)' }}>ACTIVE</span>
          </div>
        </div>
        <div className="sidebar-stat-grid">
          <div className="sidebar-stat">
            <div className="sidebar-stat-label">Hosts</div>
            <div className="sidebar-stat-value">{stats.totalHosts ?? '—'}</div>
          </div>
          <div className="sidebar-stat">
            <div className="sidebar-stat-label">Sessions</div>
            <div className="sidebar-stat-value">{stats.totalSessions ?? '—'}</div>
          </div>
          <div className="sidebar-stat" style={{ gridColumn: 'span 2' }}>
            <div className="sidebar-stat-label">Critical Alerts</div>
            <div className="sidebar-stat-value" style={{
              color: (stats.criticalHosts > 0) ? 'var(--crimson-alert)' : 'var(--sage-clear)',
              fontSize: 'var(--font-size-base)',
            }}>
              {stats.criticalHosts ?? 0} hosts
            </div>
          </div>
        </div>
      </div>

      {/* Seal */}
      <div className="sidebar-seal">
        <div className="sidebar-seal-title">
          <span>🔒</span> Passive Forensic Engine
        </div>
        <div className="sidebar-seal-desc">
          Zero network transmission. Zero payload decryption. Pure PCAP analysis.
        </div>
      </div>

      {/* Watermark / Attribution */}
      <div className="sidebar-watermark">
        <span>Project belongs to </span>
        <a
          href="https://github.com/sharmaharshit1661-web"
          target="_blank"
          rel="noopener noreferrer"
          className="sidebar-watermark-link"
        >
          @sharmaharshit1661-web
        </a>
      </div>
    </aside>
  );
}
