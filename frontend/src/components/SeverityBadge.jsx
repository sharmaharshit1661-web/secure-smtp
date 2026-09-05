export default function SeverityBadge({ severity }) {
  const sev = String(severity || 'info').toLowerCase();
  return <span className={`badge badge-${sev}`}>{sev.toUpperCase()}</span>;
}
