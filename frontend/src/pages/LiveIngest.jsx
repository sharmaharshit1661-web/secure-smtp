import { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { uploadPcap, getReportUrl } from '../api/client';
import { formatBytes } from '../utils/format';

const ATTACK_SCENARIOS = [
  {
    title: '🔴 STARTTLS Stripping Attack',
    file: 'smtp_starttls_stripped.pcap',
    desc: 'Active downgrade attack: STARTTLS advertised in EHLO but stripped from server response, forcing plaintext credentials.',
    tag: 'CRITICAL',
    tagColor: 'var(--crimson-alert)',
  },
  {
    title: '🟠 Legacy TLS 1.0 + RC4 Stream Cipher',
    file: 'smtp_tls10_rc4.pcap',
    desc: 'Deprecated TLS 1.0 protocol negotiation combined with a broken RC4 stream cipher violating NIST SP 800-52r2.',
    tag: 'HIGH',
    tagColor: 'var(--burnt-orange)',
  },
  {
    title: '🟡 Expired X.509 Certificate Chain',
    file: 'smtp_expired_cert.pcap',
    desc: 'Valid TLS handshake executed with an expired server certificate causing chain validation failure.',
    tag: 'MEDIUM',
    tagColor: 'var(--ochre-warn)',
  },
  {
    title: '🟢 Pristine TLS 1.3 Modern Baseline',
    file: 'smtp_tls13_good.pcap',
    desc: 'Hardened cryptographic configuration with TLS 1.3, AES-256-GCM AEAD cipher, and ephemeral key exchange (PFS).',
    tag: 'CLEAN',
    tagColor: 'var(--sage-clear)',
  },
  {
    title: '🟣 Enterprise Multi-Host Composite PCAP',
    file: 'demo_composite.pcap',
    desc: 'Composite network trace spanning multiple subnets with varied security postures across SMTP, IMAP, and POP3.',
    tag: 'FLEET AUDIT',
    tagColor: 'var(--amber-signal)',
  },
];

export default function LiveIngest() {
  const navigate = useNavigate();
  const fileInputRef = useRef(null);

  const [dragOver, setDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState('');
  const [resultJobId, setResultJobId] = useState(localStorage.getItem('sms_latest_job_id') || '');
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  const handleFileDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      setSelectedFile(file);
      setError(null);
    }
  };

  const handleFileSelect = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleUpload = async (fileToUpload) => {
    const file = fileToUpload || selectedFile;
    if (!file) return;

    setUploading(true);
    setError(null);
    setSuccessMsg(null);
    setUploadProgress('Reassembling TCP streams & parsing handshakes...');

    try {
      const res = await uploadPcap(file);
      const jobId = res.job_id || 'audit_completed';
      setResultJobId(jobId);
      localStorage.setItem('sms_latest_job_id', jobId);
      setSuccessMsg(`PCAP "${file.name}" analyzed successfully! Forensic telemetry ingested.`);
      setSelectedFile(null);
    } catch (err) {
      console.error('Ingestion error:', err);
      setError(err.message || 'PCAP analysis failed.');
    } finally {
      setUploading(false);
      setUploadProgress('');
    }
  };

  const handleScenarioReplay = async (scenario) => {
    setUploading(true);
    setError(null);
    setSuccessMsg(null);
    setUploadProgress(`Loading scenario: ${scenario.title}...`);

    try {
      const resp = await fetch(`/pcaps/${scenario.file}`);
      if (!resp.ok) throw new Error(`Could not load fixture ${scenario.file}`);
      const blob = await resp.blob();
      const file = new File([blob], scenario.file, { type: 'application/vnd.tcpdump.pcap' });

      setUploadProgress('Running deterministic TLS parser & AI risk attribution...');
      const res = await uploadPcap(file);
      const jobId = res.job_id || scenario.file.replace('.pcap', '');
      setResultJobId(jobId);
      localStorage.setItem('sms_latest_job_id', jobId);
      setSuccessMsg(`Scenario "${scenario.title}" ingested successfully!`);
    } catch (err) {
      console.error('Scenario replay error:', err);
      setError(err.message || 'Scenario ingestion failed.');
    } finally {
      setUploading(false);
      setUploadProgress('');
    }
  };

  return (
    <div className="flex flex-col gap-xl">
      {/* Title */}
      <div>
        <h1 className="section-header" style={{ marginBottom: 'var(--space-xs)', fontSize: 'var(--font-size-2xl)' }}>
          <span>⚡</span> Passive PCAP Ingest & Attack Replay
        </h1>
        <p className="text-secondary text-sm">
          Ingest raw network packet captures (.pcap, .pcapng) containing SMTP, IMAP, or POP3 traffic with zero decryption.
        </p>
      </div>

      {/* Notifications */}
      {error && (
        <div className="card" style={{ borderColor: 'var(--crimson-alert)', background: 'var(--crimson-glow)' }}>
          <div className="flex items-center gap-sm">
            <span style={{ fontSize: '1.5rem' }}>⚠️</span>
            <div>
              <div className="font-bold text-crimson">Ingestion Failed</div>
              <div className="text-secondary text-sm">{error}</div>
            </div>
          </div>
        </div>
      )}

      {successMsg && (
        <div className="card" style={{ borderColor: 'var(--sage-clear)', background: 'var(--sage-glow)' }}>
          <div className="flex justify-between items-center">
            <div className="flex items-center gap-sm">
              <span style={{ fontSize: '1.5rem' }}>✅</span>
              <div>
                <div className="font-bold text-sage">Analysis Complete</div>
                <div className="text-secondary text-sm">{successMsg}</div>
              </div>
            </div>
            <div className="flex gap-sm">
              <button className="btn" onClick={() => navigate('/')}>
                View Fleet Overview
              </button>
              <button className="btn btn-primary" onClick={() => navigate('/sessions')}>
                Inspect Sessions →
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-2 gap-xl">
        {/* Left Column: Upload Box + Report Downloads */}
        <div className="flex flex-col gap-xl">
          {/* Custom PCAP Upload */}
          <div className="card">
            <div className="section-header" style={{ marginBottom: 'var(--space-md)' }}>
              <span>📁</span> Upload Custom Packet Capture
            </div>
            <p className="text-secondary text-sm" style={{ marginBottom: 'var(--space-lg)' }}>
              Passive inspection: 100% offline analysis. No packets sent, no mail decrypted.
            </p>

            <input
              type="file"
              ref={fileInputRef}
              style={{ display: 'none' }}
              accept=".pcap,.pcapng,.cap"
              onChange={handleFileSelect}
            />

            <div
              className={`upload-zone ${dragOver ? 'drag-over' : ''}`}
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleFileDrop}
              onClick={() => fileInputRef.current?.click()}
            >
              <div className="upload-zone-icon">📡</div>
              <div className="upload-zone-text font-bold">
                {selectedFile ? selectedFile.name : 'Drop PCAP file here or click to browse'}
              </div>
              <div className="upload-zone-hint">
                {selectedFile
                  ? `Size: ${formatBytes(selectedFile.size)} — Ready for analysis`
                  : 'Supports .pcap, .pcapng format (up to 50 MB)'}
              </div>
            </div>

            {selectedFile && (
              <div style={{ marginTop: 'var(--space-lg)' }}>
                <button
                  className="btn btn-primary btn-full"
                  disabled={uploading}
                  onClick={() => handleUpload()}
                >
                  {uploading ? uploadProgress || 'Processing...' : `🚀 Analyze ${selectedFile.name}`}
                </button>
              </div>
            )}

            {uploading && !selectedFile && (
              <div style={{ marginTop: 'var(--space-md)', textAlign: 'center' }}>
                <div className="text-amber text-sm font-semibold">{uploadProgress}</div>
              </div>
            )}
          </div>

          {/* Executive Audit Reports Download Box */}
          <div className="card">
            <div className="section-header" style={{ marginBottom: 'var(--space-xs)' }}>
              <span>📄</span> Executive Audit Reports
            </div>
            <p className="text-secondary text-sm" style={{ marginBottom: 'var(--space-lg)' }}>
              Download boardroom-ready cryptographic audit and compliance certification reports.
            </p>

            <div className="grid grid-3 gap-sm">
              <a
                href={getReportUrl(resultJobId || 'demo_report', 'pdf')}
                target="_blank"
                rel="noreferrer"
                className="btn btn-full"
                style={{ textAlign: 'center' }}
              >
                📑 PDF Report
              </a>
              <a
                href={getReportUrl(resultJobId || 'demo_report', 'html')}
                target="_blank"
                rel="noreferrer"
                className="btn btn-full"
                style={{ textAlign: 'center' }}
              >
                🌐 HTML Report
              </a>
              <a
                href={getReportUrl(resultJobId || 'demo_report', 'json')}
                target="_blank"
                rel="noreferrer"
                className="btn btn-full"
                style={{ textAlign: 'center' }}
              >
                📊 JSON Schema
              </a>
            </div>
          </div>
        </div>

        {/* Right Column: One-Click Attack Scenarios */}
        <div className="card">
          <div className="section-header" style={{ marginBottom: 'var(--space-xs)' }}>
            <span>🎯</span> One-Click Attack Scenarios & Baselines
          </div>
          <p className="text-secondary text-sm" style={{ marginBottom: 'var(--space-lg)' }}>
            Instantly evaluate pre-packaged real-world forensic capture scenarios:
          </p>

          <div className="flex flex-col gap-md">
            {ATTACK_SCENARIOS.map((sc, i) => (
              <div key={i} className="scenario-card">
                <div className="flex justify-between items-center" style={{ marginBottom: 'var(--space-xs)' }}>
                  <div className="scenario-title">{sc.title}</div>
                  <span
                    className="badge"
                    style={{
                      borderColor: sc.tagColor,
                      color: sc.tagColor,
                      background: 'rgba(0,0,0,0.3)',
                    }}
                  >
                    {sc.tag}
                  </span>
                </div>
                <div className="scenario-desc">{sc.desc}</div>
                <button
                  className="btn btn-full"
                  disabled={uploading}
                  onClick={() => handleScenarioReplay(sc)}
                  style={{ fontSize: 'var(--font-size-xs)' }}
                >
                  ⚡ Replay Scenario ({sc.file})
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
