import { useState } from 'react';
import SeverityBadge from '../components/SeverityBadge';

const COMPLIANCE_STANDARDS = [
  {
    name: 'NIST SP 800-52r2',
    title: 'Guidelines for TLS Implementations',
    desc: 'Mandates TLS 1.2/1.3, ephemeral key exchanges (ECDHE), SHA-256+ signatures, and RSA ≥ 2048-bit.',
    status: 'ACTIVE ENFORCEMENT',
  },
  {
    name: 'PCI-DSS v4.0',
    title: 'Payment Card Security Standard',
    desc: 'Strict prohibition of legacy TLS 1.0/1.1 and early SSL. Mandates strong ciphers and trusted CA chains.',
    status: 'COMPLIANT AUDIT',
  },
  {
    name: 'RFC 8996',
    title: 'Deprecation of TLS 1.0 and TLS 1.1',
    desc: 'Formal Internet Standard declaring TLS 1.0 and TLS 1.1 obsolete. Any negotiation is flagged as high risk.',
    status: 'IETF STANDARD',
  },
];

const RULES_DATA = [
  {
    id: 'deprecated-tls-version',
    applies_to: 'handshake.tls_version_negotiated',
    condition: "value in ['SSLv3', 'TLS1.0', 'TLS1.1']",
    severity: 'high',
    standards: ['NIST SP 800-52r2', 'RFC 8996'],
    message: 'Deprecated TLS version negotiated: {value}',
    recommendation: 'Disable SSLv3/TLS 1.0/TLS 1.1 on the server; require TLS 1.2 minimum, prefer TLS 1.3.',
  },
  {
    id: 'weak-cipher',
    applies_to: 'handshake.cipher_suite_negotiated',
    condition: 'is_weak_cipher(value)',
    severity: 'high',
    standards: ['NIST SP 800-52r2', 'PCI-DSS v4.0'],
    message: 'Weak cipher suite negotiated: {value}',
    recommendation: 'Restrict server cipher list to AEAD ciphers (AES-GCM, ChaCha20-Poly1305).',
  },
  {
    id: 'no-forward-secrecy',
    applies_to: 'handshake.key_exchange_type',
    condition: "value == 'rsa'",
    severity: 'medium',
    standards: ['NIST SP 800-52r2'],
    message: 'RSA key exchange used — no forward secrecy',
    recommendation: 'Configure mail server to prefer ECDHE or DHE key exchange to preserve Perfect Forward Secrecy.',
  },
  {
    id: 'weak-cert-key-rsa',
    applies_to: 'certificate.key_length_bits',
    condition: "certificate.public_key_algorithm == 'RSA' and value < 2048",
    severity: 'high',
    standards: ['NIST SP 800-52r2', 'PCI-DSS v4.0'],
    message: 'Certificate RSA key length {value} bits is below 2048',
    recommendation: 'Reissue certificate with an RSA key >= 2048 bits, or switch to ECDSA (P-256).',
  },
  {
    id: 'weak-cert-key-ecdsa',
    applies_to: 'certificate.key_length_bits',
    condition: "certificate.public_key_algorithm == 'ECDSA' and value < 256",
    severity: 'high',
    standards: ['NIST SP 800-52r2'],
    message: 'Certificate ECDSA key length {value} bits is below 256',
    recommendation: 'Reissue certificate with an ECDSA key >= 256 bits (P-256 or stronger).',
  },
  {
    id: 'weak-cert-signature',
    applies_to: 'certificate.signature_algorithm',
    condition: "value in ['md5', 'sha1']",
    severity: 'high',
    standards: ['NIST SP 800-52r2', 'PCI-DSS v4.0'],
    message: 'Certificate signed with weak algorithm: {value}',
    recommendation: 'Reissue certificate signed with SHA-256 or stronger digest algorithm.',
  },
  {
    id: 'cert-expired',
    applies_to: 'certificate.not_after',
    condition: 'is_expired(value)',
    severity: 'critical',
    standards: ['PCI-DSS v4.0'],
    message: 'Certificate expired on {value}',
    recommendation: 'Renew and deploy active X.509 certificate immediately to prevent validation halts.',
  },
  {
    id: 'cert-expiring-soon',
    applies_to: 'certificate.not_after',
    condition: 'is_expiring_soon(value, 30)',
    severity: 'low',
    standards: ['Operational Posture'],
    message: 'Certificate expires within 30 days ({value})',
    recommendation: 'Schedule certificate automated renewal before expiration window.',
  },
  {
    id: 'self-signed-cert',
    applies_to: 'certificate.self_signed',
    condition: 'value == true',
    severity: 'medium',
    standards: ['PCI-DSS v4.0', 'NIST SP 800-52r2'],
    message: 'Certificate is self-signed',
    recommendation: 'Replace self-signed certificate with a verifiable certificate issued by a public or enterprise CA.',
  },
  {
    id: 'starttls-stripped',
    applies_to: 'session.starttls_completed',
    condition: "session.tls_mode == 'starttls' and value == false and session.starttls_advertised == true",
    severity: 'critical',
    standards: ['RFC 8996', 'NIST SP 800-52r2'],
    message: 'STARTTLS was advertised but never completed — possible downgrade/stripping attack',
    recommendation: 'Investigate for an on-path active MITM adversary; deploy MTA-STS / DANE TLSA enforcement.',
  },
  {
    id: 'no-tls',
    applies_to: 'session.tls_mode',
    condition: "value == 'none'",
    severity: 'critical',
    standards: ['NIST SP 800-52r2', 'PCI-DSS v4.0'],
    message: 'Session transmitted entirely in plaintext without any TLS encryption',
    recommendation: 'Enable TLS on the mail server. Require STARTTLS on port 25/143/110, or implicit TLS on 465/993/995.',
  },
];

export default function RulesCompliance() {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  const filteredRules = RULES_DATA.filter((r) => {
    const matchesSearch =
      !search ||
      r.id.toLowerCase().includes(search.toLowerCase()) ||
      r.message.toLowerCase().includes(search.toLowerCase()) ||
      r.applies_to.toLowerCase().includes(search.toLowerCase());
    const matchesSev = severityFilter === 'ALL' || r.severity.toLowerCase() === severityFilter.toLowerCase();
    return matchesSearch && matchesSev;
  });

  return (
    <div className="flex flex-col gap-xl">
      {/* Title */}
      <div>
        <h1 className="section-header" style={{ marginBottom: 'var(--space-xs)', fontSize: 'var(--font-size-2xl)' }}>
          <span>📋</span> Declarative Rulebook & Compliance Standards
        </h1>
        <p className="text-secondary text-sm">
          All cryptographic posture evaluations are deterministic and mapped to global standards without hardcoded heuristics.
        </p>
      </div>

      {/* Compliance Standards Banner */}
      <div className="grid grid-3">
        {COMPLIANCE_STANDARDS.map((std, i) => (
          <div key={i} className="card" style={{ padding: 'var(--space-lg)' }}>
            <div className="flex justify-between items-center" style={{ marginBottom: 'var(--space-xs)' }}>
              <div className="font-bold text-amber text-md">{std.name}</div>
              <span className="badge badge-info" style={{ fontSize: '0.65rem' }}>{std.status}</span>
            </div>
            <div className="font-semibold text-sm text-primary" style={{ marginBottom: 'var(--space-xs)' }}>
              {std.title}
            </div>
            <div className="text-secondary text-xs">{std.desc}</div>
          </div>
        ))}
      </div>

      {/* Rules Browser */}
      <div className="card">
        <div className="flex justify-between items-center" style={{ marginBottom: 'var(--space-lg)' }}>
          <div className="section-header" style={{ marginBottom: 0 }}>
            <span>🛡️</span> Evaluated Weakness Rules ({filteredRules.length})
          </div>

          <div className="flex gap-md" style={{ width: '45%' }}>
            <input
              type="text"
              className="input"
              placeholder="Search rule ID, condition, or message..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <select
              className="select"
              style={{ width: '170px' }}
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
            >
              <option value="ALL">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>

        {/* Rules List */}
        <div className="flex flex-col gap-md">
          {filteredRules.map((rule) => (
            <div key={rule.id} className={`finding-card finding-card-${rule.severity}`} style={{ marginBottom: 0 }}>
              <div className="flex justify-between items-center" style={{ marginBottom: 'var(--space-xs)' }}>
                <div className="flex items-center">
                  <SeverityBadge severity={rule.severity} />
                  <span className="finding-rule-id" style={{ fontSize: 'var(--font-size-md)' }}>
                    {rule.id}
                  </span>
                </div>
                <div className="text-mono text-xs text-muted">
                  Target Field: <span className="text-secondary">{rule.applies_to}</span>
                </div>
              </div>

              <div className="text-sm text-primary" style={{ margin: 'var(--space-sm) 0' }}>
                <span className="text-secondary font-semibold">Trigger Condition: </span>
                <code className="text-mono text-amber text-xs" style={{ background: 'var(--bg-inset)', padding: '2px 6px', borderRadius: '4px' }}>
                  {rule.condition}
                </code>
              </div>

              <div className="text-sm text-secondary" style={{ marginBottom: 'var(--space-sm)' }}>
                <strong>Message Template:</strong> {rule.message}
              </div>

              <div className="finding-remediation">
                <span>🛡️</span>
                <div>
                  <strong>Remediation Directive:</strong> {rule.recommendation}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
