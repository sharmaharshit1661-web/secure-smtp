import SeverityBadge from './SeverityBadge';
import Icon from './Icon';

export default function FindingCard({ finding }) {
  const sev = String(finding.severity || 'info').toLowerCase();
  return (
    <div className={`finding-card finding-card-${sev}`}>
      <div className="finding-header">
        <SeverityBadge severity={sev} />
        <span className="finding-rule-id">{finding.rule_id}</span>
      </div>
      <div className="finding-message">{finding.message}</div>
      {finding.recommendation && (
        <div className="finding-remediation">
          <Icon name="sparkle" size={14} />
          <div><strong>Remediation:</strong> {finding.recommendation}</div>
        </div>
      )}
    </div>
  );
}
