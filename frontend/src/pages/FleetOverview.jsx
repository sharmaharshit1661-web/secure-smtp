import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  PieChart, Pie
} from 'recharts';
import KpiCard from '../components/KpiCard';
import HostRow from '../components/HostRow';
import { getHosts } from '../api/client';
import { getBarColor, getTierColorRaw } from '../utils/colors';

export default function FleetOverview() {
  const navigate = useNavigate();
  const [hosts, setHosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState('');
  const [tierFilter, setTierFilter] = useState('ALL');

  useEffect(() => {
    fetchHosts();
  }, []);

  const fetchHosts = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getHosts();
      const sorted = (data || []).sort((a, b) => (b.aggregate_risk_score || 0) - (a.aggregate_risk_score || 0));
      setHosts(sorted);
    } catch (err) {
      console.error('Failed to fetch hosts:', err);
      setError(err.message || 'Unable to connect to backend API');
    } finally {
      setLoading(false);
    }
  };

  const totalHosts = hosts.length;
  const totalSessions = hosts.reduce((sum, h) => sum + (h.session_count || 0), 0);
  const avgRisk = totalHosts > 0
    ? hosts.reduce((sum, h) => sum + (h.aggregate_risk_score || 0), 0) / totalHosts
    : 0;
  const criticalHosts = hosts.filter((h) => (h.aggregate_risk_score || 0) >= 75).length;
  const highHosts = hosts.filter((h) => (h.aggregate_risk_score || 0) >= 50 && (h.aggregate_risk_score || 0) < 75).length;
  const mediumHosts = hosts.filter((h) => (h.aggregate_risk_score || 0) >= 25 && (h.aggregate_risk_score || 0) < 50).length;
  const cleanHosts = hosts.filter((h) => (h.aggregate_risk_score || 0) < 25).length;

  const barChartData = hosts.map((h) => ({
    ip: h.ip,
    score: Math.round(h.aggregate_risk_score || 0),
    sessions: h.session_count || 0,
    hostId: h.host_id,
  }));

  const pieChartData = [
    { name: 'Critical (≥75)', value: criticalHosts, color: getTierColorRaw('critical') },
    { name: 'High (50–74)', value: highHosts, color: getTierColorRaw('high') },
    { name: 'Medium (25–49)', value: mediumHosts, color: getTierColorRaw('medium') },
    { name: 'Clean (<25)', value: cleanHosts, color: getTierColorRaw('clean') },
  ].filter((d) => d.value > 0);

  const filteredHosts = hosts.filter((h) => {
    const matchesSearch = !search || h.ip.toLowerCase().includes(search.toLowerCase());
    const score = h.aggregate_risk_score || 0;
    if (!matchesSearch) return false;
    if (tierFilter === 'CRITICAL') return score >= 75;
    if (tierFilter === 'HIGH') return score >= 50 && score < 75;
    if (tierFilter === 'MEDIUM') return score >= 25 && score < 50;
    if (tierFilter === 'CLEAN') return score < 25;
    return true;
  });

  return (
    <div className="flex flex-col gap-xl">
      {/* Top Title Banner */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="section-header" style={{ marginBottom: 'var(--space-xs)', fontSize: 'var(--font-size-2xl)' }}>
            <span>🌐</span> Fleet Posture Overview
          </h1>
          <p className="text-secondary text-sm">
            Passive Cryptographic Posture Intelligence & Explainable AI Risk Attribution
          </p>
        </div>
        <button className="btn btn-primary" onClick={() => navigate('/ingest')}>
          <span>⚡</span> Live PCAP Ingest
        </button>
      </div>

      {/* KPI Metric Cards */}
      <div className="grid grid-5">
        <KpiCard
          label="Audited Hosts"
          value={loading ? '...' : totalHosts}
          sub="Across Monitored Subnets"
          icon="🌐"
          delay={0}
        />
        <KpiCard
          label="Evaluated Sessions"
          value={loading ? '...' : totalSessions}
          sub="SMTP / IMAP / POP3"
          icon="🔐"
          delay={1}
        />
        <KpiCard
          label="Fleet Risk Index"
          value={loading ? '...' : `${avgRisk.toFixed(1)}`}
          sub="Weighted Posture Mean"
          icon="📊"
          accentColor={avgRisk >= 50 ? 'var(--crimson-alert)' : avgRisk >= 25 ? 'var(--ochre-warn)' : 'var(--sage-clear)'}
          delay={2}
        />
        <KpiCard
          label="Critical Threats"
          value={loading ? '...' : criticalHosts}
          sub="Score ≥ 75 (Urgent Action)"
          icon="⚠️"
          accentColor="var(--crimson-alert)"
          delay={3}
        />
        <KpiCard
          label="Pristine / Good"
          value={loading ? '...' : cleanHosts}
          sub="TLS 1.3 / AEAD Compliant"
          icon="✅"
          accentColor="var(--sage-clear)"
          delay={4}
        />
      </div>

      {/* Error State */}
      {error && (
        <div className="card" style={{ borderColor: 'var(--crimson-alert)', background: 'var(--crimson-glow)' }}>
          <div className="flex items-center gap-sm">
            <span style={{ fontSize: '1.5rem' }}>⚠️</span>
            <div>
              <div className="font-bold text-crimson">Failed to load host telemetry</div>
              <div className="text-secondary text-sm">{error} — Ensure FastAPI backend is running on port 8000.</div>
            </div>
            <button className="btn" style={{ marginLeft: 'auto' }} onClick={fetchHosts}>Retry</button>
          </div>
        </div>
      )}

      {/* Charts Row */}
      {!loading && hosts.length > 0 && (
        <div className="grid grid-3-2">
          {/* Host Risk Bar Chart */}
          <div className="card">
            <div className="section-header" style={{ marginBottom: 'var(--space-md)' }}>
              <span>📊</span> Host Risk Distribution
            </div>
            <div style={{ height: 260, width: '100%' }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barChartData} margin={{ top: 15, right: 10, left: -15, bottom: 25 }}>
                  <XAxis
                    dataKey="ip"
                    stroke="var(--text-muted)"
                    tick={{ fill: 'var(--text-secondary)', fontSize: 11, fontFamily: 'var(--font-mono)' }}
                    angle={-20}
                    textAnchor="end"
                  />
                  <YAxis
                    domain={[0, 100]}
                    stroke="var(--text-muted)"
                    tick={{ fill: 'var(--text-secondary)', fontSize: 11, fontFamily: 'var(--font-mono)' }}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'var(--bg-elevated)',
                      borderColor: 'var(--border-subtle)',
                      borderRadius: 'var(--radius-sm)',
                      color: 'var(--text-primary)',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '12px',
                    }}
                    formatter={(val) => [`${val} / 100`, 'Risk Score']}
                    labelFormatter={(label) => `Host: ${label}`}
                  />
                  <Bar dataKey="score" radius={[4, 4, 0, 0]}>
                    {barChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={getBarColor(entry.score)} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Donut Tier Breakdown */}
          <div className="card">
            <div className="section-header" style={{ marginBottom: 'var(--space-md)' }}>
              <span>🛡️</span> Posture Risk Tier Breakdown
            </div>
            <div style={{ height: 260, width: '100%' }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieChartData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={85}
                    paddingAngle={4}
                    dataKey="value"
                    label={({ name, value }) => `${name}: ${value}`}
                    labelLine={false}
                  >
                    {pieChartData.map((entry, index) => (
                      <Cell key={`pie-cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'var(--bg-elevated)',
                      borderColor: 'var(--border-subtle)',
                      borderRadius: 'var(--radius-sm)',
                      color: 'var(--text-primary)',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '12px',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* Host Posture Inventory Section */}
      <div className="card">
        <div className="flex justify-between items-center" style={{ marginBottom: 'var(--space-lg)' }}>
          <div className="section-header" style={{ marginBottom: 0 }}>
            <span>🔍</span> Host Posture Inventory ({filteredHosts.length})
          </div>
          <div className="flex gap-md" style={{ width: '45%' }}>
            <input
              type="text"
              className="input"
              placeholder="Search IP or Subnet (e.g. 10.0.0.1)..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <select
              className="select"
              style={{ width: '180px' }}
              value={tierFilter}
              onChange={(e) => setTierFilter(e.target.value)}
            >
              <option value="ALL">All Risk Tiers</option>
              <option value="CRITICAL">Critical (≥75)</option>
              <option value="HIGH">High (50–74)</option>
              <option value="MEDIUM">Medium (25–49)</option>
              <option value="CLEAN">Clean (&lt;25)</option>
            </select>
          </div>
        </div>

        {/* Host Rows or Empty States */}
        {loading ? (
          <div className="flex flex-col gap-sm">
            {[1, 2, 3].map((i) => (
              <div key={i} className="skeleton" style={{ height: '64px', width: '100%' }} />
            ))}
          </div>
        ) : filteredHosts.length > 0 ? (
          <div className="flex flex-col gap-xs">
            {filteredHosts.map((host) => (
              <HostRow key={host.host_id} host={host} />
            ))}
          </div>
        ) : (
          <div className="empty-state">
            <div className="empty-state-icon">📡</div>
            <div className="font-bold text-lg text-primary" style={{ marginBottom: 'var(--space-xs)' }}>
              No Monitored Hosts Found
            </div>
            <p className="text-secondary text-sm" style={{ maxWidth: '420px', margin: '0 auto var(--space-lg)' }}>
              {search || tierFilter !== 'ALL'
                ? 'No hosts match your active search or filter criteria.'
                : 'Your database is currently empty. Run an ingestion or replay an attack scenario to begin forensics.'}
            </p>
            {!search && tierFilter === 'ALL' && (
              <button className="btn btn-primary" onClick={() => navigate('/ingest')}>
                <span>⚡</span> Ingest PCAP Trace
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
