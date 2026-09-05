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
import { getHosts, getHostDetail, getSessionDetail } from '../api/client';
import { getTierColorRaw } from '../utils/colors';

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
          } else if (!selectedHostId) {
            setSelectedHostId(sorted[0].host_id);
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
    <div className="flex flex-col gap-xl">
      {/* Title & Selectors */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="section-header" style={{ marginBottom: 'var(--space-xs)', fontSize: 'var(--font-size-2xl)' }}>
            <span>🔬</span> Forensic Session Telemetry Dossier
          </h1>
          <p className="text-secondary text-sm">
            Deep packet-level cryptographic analysis, compliance checks, and SHAP risk attribution.
          </p>
        </div>
      </div>

      {/* Selectors Bar */}
      <div className="card" style={{ padding: 'var(--space-md) var(--space-lg)' }}>
        <div className="grid grid-1-2 gap-md items-center">
          <div>
            <label className="info-item-label">Target Monitored Host</label>
            <select
              className="select"
              value={selectedHostId || ''}
              onChange={handleHostChange}
              disabled={hosts.length === 0}
            >
              {hosts.map((h) => (
                <option key={h.host_id} value={h.host_id}>
                  {h.ip} — Risk Score {Math.round(h.aggregate_risk_score || 0)} ({h.session_count} sessions)
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="info-item-label">Forensic Session Stream</label>
            <select
              className="select"
              value={selectedSessionId || ''}
              onChange={(e) => setSelectedSessionId(Number(e.target.value))}
              disabled={hostSessions.length === 0}
            >
              {hostSessions.map((s) => (
                <option key={s.session_id} value={s.session_id}>
                  Session #{s.session_id} | {s.src_ip}:{s.src_port} ➔ {s.dst_ip}:{s.dst_port} [{s.protocol?.toUpperCase()}] — Risk {Math.round(s.risk_score || 0)}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Loading & Empty States */}
      {loading || sessionLoading ? (
        <div className="flex flex-col gap-md">
          <div className="skeleton" style={{ height: '90px' }} />
          <div className="skeleton" style={{ height: '180px' }} />
          <div className="skeleton" style={{ height: '300px' }} />
        </div>
      ) : !sessionData ? (
        <div className="empty-state">
          <div className="empty-state-icon">🔍</div>
          <div className="font-bold text-lg text-primary" style={{ marginBottom: 'var(--space-xs)' }}>
            No Session Stream Selected
          </div>
          <p className="text-secondary text-sm" style={{ maxWidth: '420px', margin: '0 auto' }}>
            Select a host and session from the controls above or ingest a PCAP file to explore cryptographic telemetry.
          </p>
        </div>
      ) : (
        <>
          {/* Wire Diagram */}
          <WireDiagram session={sessionData} />

          {/* Top 3 Summary Cards */}
          <div className="grid grid-3">
            {/* Risk Gauge */}
            <div className="card flex flex-col items-center justify-center" style={{ textAlign: 'center' }}>
              <div className="text-xs uppercase tracking-wide text-muted font-semibold" style={{ marginBottom: 'var(--space-sm)' }}>
                Cryptographic Risk Gauge
              </div>
              <RiskGauge score={riskScore} tier={riskTier} size={150} />
              <div style={{ marginTop: 'var(--space-sm)' }}>
                <SeverityBadge severity={riskTier} />
              </div>
            </div>

            {/* Handshake Intelligence */}
            <div className="card flex flex-col justify-center">
              <div className="section-header" style={{ marginBottom: 'var(--space-md)', fontSize: 'var(--font-size-md)' }}>
                <span>🔐</span> Handshake Summary
              </div>
              {hs ? (
                <div className="info-grid">
                  <div>
                    <div className="info-item-label">Negotiated Version</div>
                    <div className="info-item-value text-amber">{hs.tls_version_negotiated || 'N/A'}</div>
                  </div>
                  <div>
                    <div className="info-item-label">Key Exchange</div>
                    <div className="info-item-value">{String(hs.key_exchange_type || 'N/A').toUpperCase()}</div>
                  </div>
                  <div>
                    <div className="info-item-label">Forward Secrecy</div>
                    <div className="info-item-value">
                      {hs.forward_secrecy ? (
                        <span className="text-sage font-bold">✅ PRESENT (PFS)</span>
                      ) : (
                        <span className="text-crimson font-bold">❌ NONE (STATIC RSA)</span>
                      )}
                    </div>
                  </div>
                  <div>
                    <div className="info-item-label">Cipher Suite</div>
                    <div className="info-item-value text-xs text-primary">{hs.cipher_suite_negotiated || 'N/A'}</div>
                  </div>
                </div>
              ) : (
                <div className="text-crimson text-sm font-semibold">
                  ⚠️ Plaintext session — no cryptographic handshake was negotiated.
                </div>
              )}
            </div>

            {/* Anomaly Detection */}
            <div className="card flex flex-col justify-center">
              <div className="section-header" style={{ marginBottom: 'var(--space-md)', fontSize: 'var(--font-size-md)' }}>
                <span>🧠</span> AI Anomaly Detection
              </div>
              {anomaly ? (
                <div>
                  <div style={{ marginBottom: 'var(--space-sm)' }}>
                    <SeverityBadge severity={anomaly.is_anomalous ? 'critical' : 'clean'} />
                    <span className="font-bold text-sm" style={{ marginLeft: 'var(--space-sm)' }}>
                      {anomaly.is_anomalous ? 'Unusual Anomaly' : 'Normal Conformity'}
                    </span>
                  </div>
                  <div className="text-secondary text-sm">
                    Isolation Forest Score:{' '}
                    <span className="text-mono font-bold text-primary">
                      {Number(anomaly.score || 0).toFixed(3)}
                    </span>
                  </div>
                  <div className="text-muted text-xs" style={{ marginTop: 'var(--space-xs)' }}>
                    Baseline Reference: {anomaly.baseline || 'Global Fleet'}
                  </div>
                </div>
              ) : (
                <div className="text-secondary text-sm">No anomaly model prediction available.</div>
              )}
            </div>
          </div>

          {/* Deep Tabs */}
          <div className="card" style={{ padding: 'var(--space-xl)' }}>
            <div className="tabs">
              <button
                className={`tab ${activeTab === 'handshake' ? 'active' : ''}`}
                onClick={() => setActiveTab('handshake')}
              >
                🔐 TLS Handshake & Fingerprints
              </button>
              <button
                className={`tab ${activeTab === 'certs' ? 'active' : ''}`}
                onClick={() => setActiveTab('certs')}
              >
                📜 Certificate Chain ({certs.length})
              </button>
              <button
                className={`tab ${activeTab === 'findings' ? 'active' : ''}`}
                onClick={() => setActiveTab('findings')}
              >
                ⚠️ Posture Findings ({findings.length})
              </button>
              <button
                className={`tab ${activeTab === 'shap' ? 'active' : ''}`}
                onClick={() => setActiveTab('shap')}
              >
                📊 AI Risk Attribution (SHAP)
              </button>
            </div>

            {/* Tab 1: TLS Handshake & Fingerprints */}
            {activeTab === 'handshake' && (
              hs ? (
                <div className="grid grid-2 gap-xl">
                  <div>
                    <div className="font-bold text-md text-primary" style={{ marginBottom: 'var(--space-md)' }}>
                      Handshake Parameters
                    </div>
                    <div className="flex flex-col gap-sm">
                      <div className="info-grid">
                        <div>
                          <div className="info-item-label">Negotiated TLS Version</div>
                          <div className="info-item-value text-amber">{hs.tls_version_negotiated || 'N/A'}</div>
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
                          <div className="info-item-value">{hs.forward_secrecy ? '✅ Supported' : '❌ None'}</div>
                        </div>
                      </div>
                      {hs.visibility_limited && (
                        <div className="finding-remediation" style={{ marginTop: 'var(--space-md)' }}>
                          <span>ℹ️</span>
                          <div><strong>TLS 1.3 Limited Visibility:</strong> Extensions post-ServerHello are shielded passively by design.</div>
                        </div>
                      )}
                    </div>
                  </div>

                  <div>
                    <div className="font-bold text-md text-primary" style={{ marginBottom: 'var(--space-md)' }}>
                      Cryptographic Fingerprints
                    </div>
                    <div className="flex flex-col gap-md">
                      {hs.ja3 && (
                        <div>
                          <div className="info-item-label">JA3 (Client Fingerprint)</div>
                          <code className="text-mono text-xs text-amber" style={{ wordBreak: 'break-all' }}>{hs.ja3}</code>
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
                          <code className="text-mono text-xs text-sage" style={{ wordBreak: 'break-all' }}>{hs.ja4}</code>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="empty-state">
                  <div className="empty-state-icon">⚠️</div>
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
                <div className="flex flex-col gap-xs">
                  {findings.map((f, i) => (
                    <FindingCard key={i} finding={f} />
                  ))}
                </div>
              ) : (
                <div className="empty-state">
                  <div className="empty-state-icon">🎉</div>
                  <div className="font-bold text-md text-primary">Pristine Posture</div>
                  <p className="text-secondary text-sm">Zero cryptographic weaknesses or compliance infractions detected.</p>
                </div>
              )
            )}

            {/* Tab 4: AI Risk Attribution (SHAP) */}
            {activeTab === 'shap' && (
              <div className="flex flex-col gap-xl">
                <div className="flex items-center gap-md">
                  <span className="text-sm text-secondary">Scoring Engine:</span>
                  <code className="text-mono text-amber text-sm font-bold">
                    {explanation?.method || 'Rule Weighted + XGBoost Calibration'}
                  </code>
                </div>

                <div className="grid grid-2 gap-xl">
                  {/* Vulnerability Feature Contributions */}
                  <div>
                    <div className="font-bold text-sm text-primary" style={{ marginBottom: 'var(--space-md)' }}>
                      Vulnerability Feature Contributions
                    </div>
                    {contributions.length > 0 ? (
                      <div style={{ height: 250, width: '100%' }}>
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart data={contributions} margin={{ top: 10, right: 10, left: -20, bottom: 25 }}>
                            <XAxis
                              dataKey="name"
                              stroke="var(--text-muted)"
                              tick={{ fill: 'var(--text-secondary)', fontSize: 10, fontFamily: 'var(--font-mono)' }}
                              angle={-20}
                              textAnchor="end"
                            />
                            <YAxis
                              stroke="var(--text-muted)"
                              tick={{ fill: 'var(--text-secondary)', fontSize: 10, fontFamily: 'var(--font-mono)' }}
                              unit="%"
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
                              formatter={(val) => [`${val}%`, 'Impact Contribution']}
                            />
                            <Bar dataKey="percentage" radius={[4, 4, 0, 0]}>
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
                    <div className="font-bold text-sm text-primary" style={{ marginBottom: 'var(--space-md)' }}>
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
                            <XAxis
                              type="number"
                              stroke="var(--text-muted)"
                              tick={{ fill: 'var(--text-secondary)', fontSize: 10, fontFamily: 'var(--font-mono)' }}
                            />
                            <YAxis
                              type="category"
                              dataKey="feature"
                              stroke="var(--text-muted)"
                              tick={{ fill: 'var(--text-secondary)', fontSize: 10, fontFamily: 'var(--font-mono)' }}
                              width={110}
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
                              formatter={(val) => [val, 'SHAP Value']}
                            />
                            <Bar dataKey="impact" radius={[0, 4, 4, 0]}>
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
