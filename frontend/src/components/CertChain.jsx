import { useState } from 'react';
import { formatDate } from '../utils/format';

export default function CertChain({ certificates = [] }) {
  if (!certificates.length) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">📜</div>
        <p>No X.509 certificates exchanged (plaintext or TLS 1.3 encrypted handshake).</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-sm">
      {certificates.map((cert, i) => (
        <CertNode key={i} cert={cert} defaultOpen={i === 0} />
      ))}
    </div>
  );
}

function CertNode({ cert, defaultOpen }) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className="expander">
      <button className="expander-trigger" onClick={() => setOpen(!open)}>
        <span>📜 Certificate [{cert.chain_position}] — {cert.subject?.slice(0, 50)}</span>
        <span className={`expander-chevron ${open ? 'open' : ''}`}>▼</span>
      </button>
      {open && (
        <div className="expander-content">
          <div className="info-grid">
            <div>
              <div className="info-item-label">Subject</div>
              <div className="info-item-value">{cert.subject}</div>
            </div>
            <div>
              <div className="info-item-label">Issuer</div>
              <div className="info-item-value">{cert.issuer}</div>
            </div>
            <div>
              <div className="info-item-label">Valid From</div>
              <div className="info-item-value">{formatDate(cert.not_before)}</div>
            </div>
            <div>
              <div className="info-item-label">Valid Until</div>
              <div className="info-item-value">{formatDate(cert.not_after)}</div>
            </div>
            <div>
              <div className="info-item-label">Public Key</div>
              <div className="info-item-value">{cert.public_key_algorithm} ({cert.key_length_bits} bits)</div>
            </div>
            <div>
              <div className="info-item-label">Signature Algorithm</div>
              <div className="info-item-value">{cert.signature_algorithm}</div>
            </div>
            <div>
              <div className="info-item-label">Self-Signed</div>
              <div className="info-item-value">{cert.self_signed ? '⚠️ YES' : '✅ No'}</div>
            </div>
            <div>
              <div className="info-item-label">Chain Valid</div>
              <div className="info-item-value">{cert.chain_valid ? '✅ VALID' : '❌ INVALID'}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
