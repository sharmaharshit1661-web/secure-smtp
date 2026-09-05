const LABELS = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  clean: 'Clean',
  info: 'Info',
};

export default function SeverityBadge({ severity }) {
  const sev = String(severity || 'info').toLowerCase();
  return <span className={`badge badge-${sev}`}>{LABELS[sev] || sev}</span>;
}
