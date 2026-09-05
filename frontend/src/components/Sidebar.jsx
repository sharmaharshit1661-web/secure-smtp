import { NavLink } from 'react-router-dom';
import Icon from './Icon';

const NAV_ITEMS = [
  { to: '/', label: 'Fleet Overview', icon: 'globe' },
  { to: '/sessions', label: 'Session Explorer', icon: 'microscope' },
  { to: '/ingest', label: 'Live Ingest', icon: 'bolt' },
  { to: '/rules', label: 'Rules & Compliance', icon: 'clipboard' },
];

export default function Sidebar({ stats = {}, isOpen, onClose }) {
  return (
    <aside className={`app-sidebar ${isOpen ? 'open' : ''}`}>
      {/* Brand */}
      <div className="sidebar-brand">
        <div className="sidebar-logo">
          <Icon name="shield" size={19} strokeWidth={1.8} />
        </div>
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
            <span className="sidebar-link-icon">
              <Icon name={icon} size={16} />
            </span>
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-spacer" />

      {/* Live Telemetry Widget */}
      <div className="sidebar-telemetry">
        <div className="sidebar-telemetry-header">
          <span>Live Telemetry</span>
          <div className="status-beacon">
            <span className="status-dot status-dot-active" />
            <span style={{ color: 'var(--sev-clean)' }}>ACTIVE</span>
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
            <div
              className="sidebar-stat-value"
              style={{
                color: stats.criticalHosts > 0 ? 'var(--sev-critical)' : 'var(--sev-clean)',
                fontSize: 'var(--fs-base)',
              }}
            >
              {stats.criticalHosts ?? 0} hosts
            </div>
          </div>
        </div>
      </div>

      {/* Seal */}
      <div className="sidebar-seal">
        <div className="sidebar-seal-title">
          <Icon name="lock" size={14} />
          <span>Passive Forensic Engine</span>
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