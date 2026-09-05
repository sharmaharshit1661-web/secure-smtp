import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell
} from 'recharts';
import RiskGauge from '../components/RiskGauge';
import WireDiagram from '../components/WireDiagram';
import FindingCard from '../components/FindingCard';
import CertChain from '../components/CertChain';
import SeverityBadge from '../components/SeverityBadge';
import Icon from '../components/Icon';
import { getHosts, getHostDetail, getSessionDetail } from '../api/client';
import { getTierColorRaw } from '../utils/colors';

const TOOLTIP_STYLE = {
  backgroundColor: 'var(--bg-elevated)',
  border: '1px solid var(--border-strong)',
  borderRadius: '10px',
  color: 'var(--text-primary)',
  fontFamily: 'var(--font-mono)',
  fontSize: '12px',
  boxShadow: 'var(--shadow-md)',
};

export default function SessionExplorer() {
  const { hostId: routeHostId } = useParams();
  const navigate = useNavigate();

  const [hosts, setHosts] = useState([]);
  const [selectedHostId, setSelectedHostId] = useState(routeHostId ? Number(routeHostId) : null);
  const [hostSessions, setHostSessions] = useState([]);
  const [selectedSessionId, setSelectedSessionId] = useState(null);
  const [sessionData, setSessionData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [sessionLoading, setSessionLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('handshake');

  // Fetch host list
  useEffect(() => {
    getHosts()
      .then((data) => {
        const sorted = (data || []).sort((a, b) => (b.aggregate_risk_score || 0) - (a.aggregate_risk_score || 0));
        setHosts(sorted);
        if (sorted.length > 0) {
          if (routeHostId) {
            setSelectedHostId(Number(routeHostId));
          } else {
            setSelectedHostId((prev) => prev || sorted[0].host_id);
          }
        }
      })
      .catch((err) => console.error('Failed to load hosts:', err));
  }, [routeHostId]);

  // When selectedHostId changes, fetch host sessions
  useEffect(() => {
    if (!selectedHostId) return;
    setLoading(true);
    getHostDetail(selectedHostId)
      .then((detail) => {
        const sessList = detail?.sessions || [];
        setHostSessions(sessList);
        if (sessList.length > 0) {
          setSelectedSessionId(sessList[0].session_id);
        } else {
          setSelectedSessionId(null);
          setSessionData(null);
        }
      })
      .catch((err) => {
        console.error('Failed to load host detail:', err);
        setHostSessions([]);
      })
      .finally(() => setLoading(false));
  }, [selectedHostId]);

  // When selectedSessionId changes, fetch deep session details
  useEffect(() => {
    if (!selectedSessionId) return;
    setSessionLoading(true);
    getSessionDetail(selectedSessionId)
      .then((detail) => {
        setSessionData(detail);
      })
      .catch((err) => {
        console.error('Failed to load session telemetry:', err);
        setSessionData(null);
      })
      .finally(() => setSessionLoading(false));
  }, [selectedSessionId]);

  const handleHostChange = (e) => {
    const newId = Number(e.target.value);
    setSelectedHostId(newId);
    navigate(`/sessions/${newId}`);
  };

  const hs = sessionData?.handshake;
  const riskScore = sessionData?.risk_score?.score ?? 0;
  const riskTier = sessionData?.risk_score?.tier ?? 'clean';
  const anomaly = sessionData?.anomaly_score;
  const findings = sessionData?.findings || [];
  const certs = sessionData?.certificates || [];

  // Parse SHAP / AI Explanation
  let explanation = sessionData?.risk_score?.explanation;
  if (typeof explanation === 'string') {
    try {
      explanation = JSON.parse(explanation);
    } catch {
      explanation = {};
    }
  }

  const contributions = (explanation?.contributions || []).map((c) => ({
    name: c.rule_id,
    percentage: Math.round(c.percentage || 0),
    severity: c.severity || 'info',
    color: getTierColorRaw(c.severity || 'info'),
  }));

  const shapValues = explanation?.shap_values || {};
  const shapChartData = Object.entries(shapValues)
    .sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]))
    .slice(0, 8)
    .map(([feature, val]) => ({
      feature,
      impact: Number(Number(val).toFixed(3)),
      color: val > 0 ? getTierColorRaw('critical') : getTierColorRaw('clean'),
    }));

  return (
    <div className="flex flex-col gap-5">
      {/* Title & Selectors */}
      <div className="page-header animate-in">
        <div>
          <h1 className="page-title">
            <span className="page-title-icon"><Icon name="microscope" size={20} /></span>
            Forensic Session Telemetry Dossier
          </h1>
          <p className="page-subtitle">
            Deep packet-level cryptographic analysis, compliance checks, and SHAP risk attribution.
          </p>
        </div>
      </div>

      {/* Selectors Bar */}
      <div className="card animate-in animate-in-1" style={{ padding: 'var(--space-3) var(--space-4)' }}>
        <div className="grid grid-1-2 gap-3 items-center">
          <div>
            <label className="field-label">Target Monitored Host</label>
            <select
              className="select"
              value={selectedHostId || ''}
              onChange={handleHostChange}
              disabled={hosts.length === 0}
            >
              {hosts.map((h) => (
                <option key={h.host_id} value={h.host_id}>
                  {h.ip} — Risk {Math.round(h.aggregate_risk_score || 0)} ({h.session_count} sessions)
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="field-label">Forensic Session Stream</label>
            <select
              className="select"
              value={selectedSessionId || ''}
              onChange={(e) => setSelectedSessionId(Number(e.target.value))}
              disabled={hostSessions.length === 0}
            >
              {hostSessions.map((s) => (
                <option key={s.session_id} value={s.session_id}>
                  Session #{s.session_id} | {s.src_ip}:{s.src_port} → {s.dst_ip}:{s.dst_port} [{s.protocol?.toUpperCase()}] — Risk {Math.round(s.risk_score || 0)}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Loading & Empty States */}
      {loading || sessionLoading ? (
        <div className="flex flex-col gap-3">
          <div className="skeleton" style={{ height: '90px' }} />
          <div className="skeleton" style={{ height: '180px' }} />
          <div className="skeleton" style={{ height: '300px' }} />
        </div>
      ) : !sessionData ? (
        <div className="empty-state">
          <div className="empty-state-icon"><Icon name="search" size={24} /></div>
          <div className="font-bold text-md text-primary" style={{ marginBottom: 'var(--space-1)' }}>
            No Session Stream Selected
          </div>
          <p className="text-secondary text-sm" style={{ maxWidth: '420px', margin: '0 auto' }}>
            Select a host and session from the controls above or ingest a PCAP file to explore cryptographic telemetry.
          </p>
        </div>
      ) : (
        <>
          {/* Wire Diagram */}
          <div className="animate-in animate-in-2">
            <WireDiagram session={sessionData} />
          </div>

          {/* Top 3 Summary Cards */}
          <div className="grid grid-3">
            {/* Risk Gauge */}
            <div className="card card-hover flex flex-col items-center justify-center animate-in animate-in-3" style={{ textAlign: 'center' }}>
              <div className="kpi-label" style={{ marginBottom: 'var(--space-3)' }}>
                Cryptographic Risk Gauge
              </div>
              <RiskGauge score={riskScore} tier={riskTier} size={150} />
              <div style={{ marginTop: 'var(--space-2)' }}>
                <SeverityBadge severity={riskTier} />
              </div>
            </div>

            {/* Handshake Intelligence */}
            <div className="card card-hover flex flex-col justify-center animate-in animate-in-3">
              <div className="section-header" style={{ marginBottom: 'var(--space-4)' }}>
                <Icon name="lock" size={15} /> Handshake Summary
              </div>
              {hs ? (
                <div className="info-grid">
                  <div>
                    <div className="info-item-label">Negotiated Version</div>
                    <div className="info-item-value text-accent">{hs.tls_version_negotiated || 'N/A'}</div>
                  </div>
                  <div>
                    <div className="info-item-label">Key Exchange</div>
                    <div className="info-item-value">{String(hs.key_exchange_type || 'N/A').toUpperCase()}</div>
                  </div>
                  <div>
                    <div className="info-item-label">Forward Secrecy</div>
                    <div className="info-item-value">
                      {hs.forward_secrecy ? (
                        <span className="text-clean font-semibold">Present (PFS)</span>
                      ) : (
                        <span className="text-critical font-semibold">None (Static RSA)</span>
                      )}
                    </div>
                  </div>
                  <div>
                    <div className="info-item-label">Cipher Suite</div>
                    <div className="info-item-value text-xs">{hs.cipher_suite_negotiated || 'N/A'}</div>
                  </div>
                </div>
              ) : (
                <div className="text-critical text-sm font-semibold flex items-center gap-2">
                  <Icon name="alert" size={15} /> Plaintext session — no cryptographic handshake was negotiated.
                </div>
              )}
            </div>

            {/* Anomaly Detection */}
            <div className="card card-hover flex flex-col justify-center animate-in animate-in-3">
              <div className="section-header" style={{ marginBottom: 'var(--space-4)' }}>
                <Icon name="brain" size={15} /> AI Anomaly Detection
              </div>
              {anomaly ? (
                <div>
                  <div className="flex items-center gap-2" style={{ marginBottom: 'var(--space-2)' }}>
                    <SeverityBadge severity={anomaly.is_anomalous ? 'critical' : 'clean'} />
                    <span className="font-semibold text-sm">
                      {anomaly.is_anomalous ? 'Unusual Anomaly' : 'Normal Conformity'}
                    </span>
                  </div>
                  <div className="text-secondary text-sm">
                    Isolation Forest Score:{' '}
                    <span className="text-mono font-bold text-primary">
                      {Number(anomaly.score || 0).toFixed(3)}
                    </span>
                  </div>
                  <div className="text-muted text-xs" style={{ marginTop: 'var(--space-1)' }}>
                    Baseline Reference: {anomaly.baseline || 'Global Fleet'}
                  </div>
                </div>
              ) : (
                <div className="text-secondary text-sm">No anomaly model prediction available.</div>
              )}
            </div>
          </div>

          {/* Deep Tabs */}
          <div className="card animate-in animate-in-4" style={{ padding: 'var(--space-5)' }}>
            <div className="tabs">
              <button
                className={`tab ${activeTab === 'handshake' ? 'active' : ''}`}
                onClick={() => setActiveTab('handshake')}
              >
                <Icon name="lock" size={14} /> TLS Handshake &amp; Fingerprints
              </button>
              <button
                className={`tab ${activeTab === 'certs' ? 'active' : ''}`}
                onClick={() => setActiveTab('certs')}
              >
                <Icon name="certificate" size={14} /> Certificate Chain ({certs.length})
              </button>
              <button
                className={`tab ${activeTab === 'findings' ? 'active' : ''}`}
                onClick={() => setActiveTab('findings')}
              >
                <Icon name="alert" size={14} /> Posture Findings ({findings.length})
              </button>
              <button
                className={`tab ${activeTab === 'shap' ? 'active' : ''}`}
                onClick={() => setActiveTab('shap')}
              >
                <Icon name="chart" size={14} /> AI Risk Attribution (SHAP)
              </button>
            </div>

            {/* Tab 1: TLS Handshake & Fingerprints */}
            {activeTab === 'handshake' && (
              hs ? (
                <div className="grid grid-2 gap-5">
                  <div>
                    <div className="font-bold text-md text-primary" style={{ marginBottom: 'var(--space-3)' }}>
                      Handshake Parameters
                    </div>
                    <div className="flex flex-col gap-2">
                      <div className="info-grid">
                        <div>
                          <div className="info-item-label">Negotiated TLS Version</div>
                          <div className="info-item-value text-accent">{hs.tls_version_negotiated || 'N/A'}</div>
                        </div>
                        <div>
                          <div className="info-item-label">Cipher Suite</div>
                          <div className="info-item-value">{hs.cipher_suite_negotiated || 'N/A'}</div>
                        </div>
                        <div>
                          <div className="info-item-label">Key Exchange Type</div>
                          <div className="info-item-value">{String(hs.key_exchange_type || 'N/A').toUpperCase()}</div>
                        </div>
                        <div>
                          <div className="info-item-label">Forward Secrecy</div>
                          <div className="info-item-value">{hs.forward_secrecy ? 'Supported' : 'None'}</div>
                        </div>
                      </div>
                      {hs.visibility_limited && (
                        <div className="finding-remediation" style={{ marginTop: 'var(--space-3)' }}>
                          <Icon name="info" size={14} />
                          <div><strong>TLS 1.3 Limited Visibility:</strong> Extensions post-ServerHello are shielded passively by design.</div>
                        </div>
                      )}
                    </div>
                  </div>

                  <div>
                    <div className="font-bold text-md text-primary" style={{ marginBottom: 'var(--space-3)' }}>
                      Cryptographic Fingerprints
                    </div>
                    <div className="flex flex-col gap-3">
                      {hs.ja3 && (
                        <div>
                          <div className="info-item-label">JA3 (Client Fingerprint)</div>
                          <code className="text-mono text-xs text-accent" style={{ wordBreak: 'break-all' }}>{hs.ja3}</code>
                        </div>
                      )}
                      {hs.ja3s && (
                        <div>
                          <div className="info-item-label">JA3S (Server Fingerprint)</div>
                          <code className="text-mono text-xs text-secondary" style={{ wordBreak: 'break-all' }}>{hs.ja3s}</code>
                        </div>
                      )}
                      {hs.ja4 && (
                        <div>
                          <div className="info-item-label">JA4 (Modern High-Assurance Fingerprint)</div>
                          <code className="text-mono text-xs text-clean" style={{ wordBreak: 'break-all' }}>{hs.ja4}</code>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="empty-state">
                  <div className="empty-state-icon"><Icon name="alert" size={24} /></div>
                  <p>No TLS Handshake data exists for unencrypted plaintext traffic.</p>
                </div>
              )
            )}

            {/* Tab 2: Certificate Chain */}
            {activeTab === 'certs' && (
              <CertChain certificates={certs} />
            )}

            {/* Tab 3: Posture Findings */}
            {activeTab === 'findings' && (
              findings.length > 0 ? (
                <div className="flex flex-col gap-1">
                  {findings.map((f, i) => (
                    <div key={i} className="animate-in" style={{ animationDelay: `${Math.min(i * 40, 240)}ms` }}>
                      <FindingCard finding={f} />
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state">
                  <div className="empty-state-icon"><Icon name="check" size={24} /></div>
                  <div className="font-bold text-md text-primary">Pristine Posture</div>
                  <p className="text-secondary text-sm">Zero cryptographic weaknesses or compliance infractions detected.</p>
                </div>
              )
            )}

            {/* Tab 4: AI Risk Attribution (SHAP) */}
            {activeTab === 'shap' && (
              <div className="flex flex-col gap-5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-sm text-secondary">Scoring Engine:</span>
                  <code className="text-mono text-accent text-sm font-bold">
                    {explanation?.method || 'Rule Weighted + XGBoost Calibration'}
                  </code>
                </div>

                <div className="grid grid-2 gap-5">
                  {/* Vulnerability Feature Contributions */}
                  <div>
                    <div className="font-bold text-sm text-primary" style={{ marginBottom: 'var(--space-3)' }}>
                      Vulnerability Feature Contributions
                    </div>
                    {contributions.length > 0 ? (
                      <div style={{ height: 250, width: '100%' }}>
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart data={contributions} margin={{ top: 10, right: 10, left: -20, bottom: 25 }}>
                            <XAxis dataKey="name" stroke="var(--text-muted)" tick={{ fill: 'var(--text-secondary)', fontSize: 10, fontFamily: 'var(--font-mono)' }} angle={-20} textAnchor="end" />
                            <YAxis stroke="var(--text-muted)" tick={{ fill: 'var(--text-secondary)', fontSize: 10, fontFamily: 'var(--font-mono)' }} unit="%" />
                            <Tooltip
                              contentStyle={TOOLTIP_STYLE}
                              cursor={{ fill: 'rgba(255,255,255,0.04)' }}
                              formatter={(val) => [`${val}%`, 'Impact Contribution']}
                            />
                            <Bar dataKey="percentage" radius={[5, 5, 0, 0]} maxBarSize={34}>
                              {contributions.map((entry, index) => (
                                <Cell key={`contrib-${index}`} fill={entry.color} />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                    ) : (
                      <div className="text-secondary text-sm">No vulnerability features active for this session.</div>
                    )}
                  </div>

                  {/* SHAP Feature Attribution Waterfall */}
                  <div>
                    <div className="font-bold text-sm text-primary" style={{ marginBottom: 'var(--space-3)' }}>
                      SHAP Feature Attribution (Impact on Risk)
                    </div>
                    {shapChartData.length > 0 ? (
                      <div style={{ height: 250, width: '100%' }}>
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart
                            layout="vertical"
                            data={shapChartData}
                            margin={{ top: 10, right: 20, left: 40, bottom: 5 }}
                          >
                            <XAxis type="number" stroke="var(--text-muted)" tick={{ fill: 'var(--text-secondary)', fontSize: 10, fontFamily: 'var(--font-mono)' }} />
                            <YAxis
                              type="category"
                              dataKey="feature"
                              stroke="var(--text-muted)"
                              tick={{ fill: 'var(--text-secondary)', fontSize: 10, fontFamily: 'var(--font-mono)' }}
                              width={110}
                            />
                            <Tooltip
                              contentStyle={TOOLTIP_STYLE}
                              cursor={{ fill: 'rgba(255,255,255,0.04)' }}
                              formatter={(val) => [val, 'SHAP Value']}
                            />
                            <Bar dataKey="impact" radius={[0, 5, 5, 0]} maxBarSize={16}>
                              {shapChartData.map((entry, index) => (
                                <Cell key={`shap-${index}`} fill={entry.color} />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                    ) : (
                      <div className="text-secondary text-sm">No SHAP explanation vector available.</div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
