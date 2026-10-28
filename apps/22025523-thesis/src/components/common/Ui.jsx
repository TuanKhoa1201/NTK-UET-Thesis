import SafeIcon from '../../common/SafeIcon';

export function Icon({ name, ...props }) {
  return <SafeIcon name={name} {...props} />;
}

export function PageHeader({ eyebrow, title, description, actions }) {
  return (
    <div className="page-header">
      <div>
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  );
}

export function Card({ children, className = '', title, action }) {
  return (
    <section className={`card ${className}`}>
      {(title || action) && <div className="card-heading"><h3>{title}</h3>{action}</div>}
      {children}
    </section>
  );
}

export function Badge({ children, tone = 'neutral' }) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

export function StatCard({ label, value, note, icon, tone = 'blue' }) {
  return (
    <div className="stat-card">
      <div className={`stat-icon tone-${tone}`}><Icon name={icon} /></div>
      <div className="stat-label">{label}</div>
      <strong>{value}</strong>
      <small>{note}</small>
    </div>
  );
}

export function EmptyState({ title, text, icon = 'Inbox' }) {
  return <div className="empty-state"><Icon name={icon} /><strong>{title}</strong><p>{text}</p></div>;
}

export function DataNotice({ children }) {
  return <div className="notice"><Icon name="Info" /><span>{children}</span></div>;
}

export function BarRow({ label, value, max, color = 'blue', suffix = '' }) {
  const width = max ? Math.min((value / max) * 100, 100) : 0;
  return (
    <div className="bar-row">
      <div className="bar-meta"><span>{label}</span><strong>{value}{suffix}</strong></div>
      <div className="bar-track"><div className={`bar-fill ${color}`} style={{ width: `${width}%` }} /></div>
    </div>
  );
}

export function SectionTitle({ title, text }) {
  return <div className="section-title"><h2>{title}</h2>{text && <p>{text}</p>}</div>;
}