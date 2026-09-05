export default function KpiCard({ label, value, sub, icon, accentColor, className = '', delay = 0 }) {
  return (
    <div
      className={`kpi-card animate-in animate-in-${delay + 1} ${className}`}
      style={{ '--kpi-accent': accentColor }}
    >
      <div className="kpi-label">
        <span>{label}</span>
        {icon && <span>{icon}</span>}
      </div>
      <div className="kpi-value" style={accentColor ? { color: accentColor } : undefined}>
        {value}
      </div>
      {sub && <div className="kpi-sub">{sub}</div>}
    </div>
  );
}
