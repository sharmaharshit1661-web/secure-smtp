import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  PieChart, Pie
} from 'recharts';
import KpiCard from '../components/KpiCard';
import HostRow from '../components/HostRow';
import Icon from '../components/Icon';
import { getHosts } from '../api/client';
import { getBarColor, getTierColorRaw } from '../utils/colors';

const TOOLTIP_STYLE = {
  backgroundColor: 'var(--bg-elevated)',
  border: '1px solid var(--border-strong)',
  borderRadius: '10px',
  color: 'var(--text-primary)',
  fontFamily: 'var(--font-mono)',
  fontSize: '12px',
  boxShadow: 'var(--shadow-md)',
};

export default function FleetOverview() {
  const navigate = useNavigate();
  const [hosts, setHosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState('');
  const [tierFilter, setTierFilter] = useState('ALL');

  const fetchHosts = async (isManual = false) => {
    if (isManual) setLoading(true);
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

  useEffect(() => {
    fetchHosts();
  }, []);

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
    <div className="flex flex-col gap-5">
      <div className="page-header animate-in">
        <div>
          <h1 className="page-title">
            <span className="page-title-icon"><Icon name="globe" size={20} /></span>
            Fleet Posture Overview
          </h1>
          <p className="page-subtitle">
            Passive cryptographic posture intelligence &amp; explainable AI risk attribution
            across every monitored mail host.
          </p>
        </div>
        <button className="btn btn-primary" onClick={() => navigate('/ingest')}>
          <Icon name="bolt" size={14} /> Live PCAP Ingest
        </button>
      </div>

      <div className="grid grid-5">
        <KpiCard label="Audited Hosts" value={loading ? '…' : totalHosts} sub="Across monitored subnets" icon="globe" delay={0} />
        <KpiCard label="Evaluated Sessions" value={loading ? '…' : totalSessions} sub="SMTP / IMAP / POP3" icon="lock" delay={1} />
        <KpiCard
          label="Fleet Risk Index"
          value={loading ? '…' : Number(avgRisk.toFixed(1))}
          sub="Weighted posture mean"
          icon="chart"
          accentColor={avgRisk >= 50 ? 'var(--sev-critical)' : avgRisk >= 25 ? 'var(--sev-medium)' : 'var(--sev-clean)'}
          delay={2}
        />
        <KpiCard label="Critical Threats" value={loading ? '…' : criticalHosts} sub="Score ≥ 75 — urgent action" icon="alert" accentColor="var(--sev-critical)" delay={3} />
        <KpiCard label="Pristine / Good" value={loading ? '…' : cleanHosts} sub="TLS 1.3 / AEAD compliant" icon="check" accentColor="var(--sev-clean)" delay={4} />
      </div>

      {error && (
        <div className="alert alert-critical animate-in">
          <span className="alert-icon"><Icon name="alert" size={18} /></span>
          <div className="flex-1">
            <div className="font-semibold text-critical">Failed to load host telemetry</div>
            <div className="text-secondary text-sm">{error} — ensure the FastAPI backend is running on port 8000.</div>
          </div>
          <button className="btn" onClick={() => fetchHosts(true)}>Retry</button>
        </div>
      )}

      {!loading && hosts.length > 0 && (
        <div className="grid grid-3-2">
          <div className="card card-hover animate-in animate-in-2">
            <div className="section-header" style={{ marginBottom: 'var(--space-4)' }}>
              <Icon name="chart" size={16} /> Host Risk Distribution
            </div>
            <div style={{ height: 260, width: '100%' }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barChartData} margin={{ top: 15, right: 10, left: -15, bottom: 25 }}>
                  <XAxis dataKey="ip" stroke="var(--text-muted)" tick={{ fill: 'var(--text-secondary)', fontSize: 11, fontFamily: 'var(--font-mono)' }} angle={-20} textAnchor="end" />
                  <YAxis domain={[0, 100]} stroke="var(--text-muted)" tick={{ fill: 'var(--text-secondary)', fontSize: 11, fontFamily: 'var(--font-mono)' }} />
                  <Tooltip
                    contentStyle={TOOLTIP_STYLE}
                    cursor={{ fill: 'rgba(255,255,255,0.04)' }}
                    formatter={(val) => [`${val} / 100`, 'Risk Score']}
                    labelFormatter={(label) => `Host: ${label}`}
                  />
                  <Bar dataKey="score" radius={[5, 5, 0, 0]} maxBarSize={38}>
                    {barChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={getBarColor(entry.score)} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="card card-hover animate-in animate-in-3">
            <div className="section-header" style={{ marginBottom: 'var(--space-4)' }}>
              <Icon name="shield" size={16} /> Posture Risk Tier Breakdown
            </div>
            <div style={{ height: 260, width: '100%' }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieChartData}
                    cx="50%"
                    cy="50%"
                    innerRadius={58}
                    outerRadius={88}
                    paddingAngle={4}
                    dataKey="value"
                    label={({ name, value }) => `${name}: ${value}`}
                    labelLine={false}
                  >
                    {pieChartData.map((entry, index) => (
                      <Cell key={`pie-cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      <div className="card animate-in animate-in-4">
        <div className="flex justify-between items-center flex-wrap gap-3" style={{ marginBottom: 'var(--space-4)' }}>
          <div className="section-header">
            <Icon name="search" size={16} /> Host Posture Inventory ({filteredHosts.length})
          </div>
          <div className="flex gap-2" style={{ width: 'min(45%, 460px)' }}>
            <input
              type="text"
              className="input"
              placeholder="Search IP or subnet (e.g. 10.0.0.1)…"
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

        {loading ? (
          <div className="flex flex-col gap-2">
            {[1, 2, 3].map((i) => (
              <div key={i} className="skeleton" style={{ height: '64px', width: '100%' }} />
            ))}
          </div>
        ) : filteredHosts.length > 0 ? (
          <div className="flex flex-col gap-1">
            {filteredHosts.map((host, i) => (
              <div key={host.host_id} className="animate-in" style={{ animationDelay: `${Math.min(i * 40, 320)}ms` }}>
                <HostRow host={host} />
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-state">
            <div className="empty-state-icon"><Icon name="radar" size={24} /></div>
            <div className="font-bold text-md text-primary" style={{ marginBottom: 'var(--space-1)' }}>
              No Monitored Hosts Found
            </div>
            <p className="text-secondary text-sm" style={{ maxWidth: '420px', margin: '0 auto var(--space-4)' }}>
              {search || tierFilter !== 'ALL'
                ? 'No hosts match your active search or filter criteria.'
                : 'Your database is currently empty. Run an ingestion or replay an attack scenario to begin forensics.'}
            </p>
            {!search && tierFilter === 'ALL' && (
              <button className="btn btn-primary" onClick={() => navigate('/ingest')}>
                <Icon name="bolt" size={14} /> Ingest PCAP Trace
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
