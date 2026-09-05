import SeverityBadge from './SeverityBadge';

export default function FindingCard({ finding }) {
  const sev = String(finding.severity || 'info').toLowerCase();
  return (
    <div className={`finding-card finding-card-${sev}`}>
      <div className="finding-header">
        <div className="flex items-center">
          <SeverityBadge severity={sev} />
          <span className="finding-rule-id">{finding.rule_id}</span>
        </div>
      </div>
      <div className="finding-message">{finding.message}</div>
      {finding.recommendation && (
        <div className="finding-remediation">
          <span>💡</span>
          <div><strong>Remediation:</strong> {finding.recommendation}</div>
        </div>
      )}
    </div>
  );
}
