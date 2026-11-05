import { PLATFORM, STANDING, STAGE } from '../lib/constants';

export function PlatformBadge({ platform }) {
  const key = platform?.toLowerCase();
  const meta = PLATFORM[key] || { label: platform || 'Unknown' };
  return (
    <span className="inline-flex items-center px-2.5 py-1 rounded text-xs font-medium bg-surface-lg text-titles-and-attributes border border-border-faint">
      {meta.label}
    </span>
  );
}

export function StandingBadge({ standing }) {
  const meta = STANDING[standing] || STANDING.untagged;
  const isCurrent = standing === 'n';
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium border ${meta.badge}`}>
      <span
        className={`w-1.5 h-1.5 rounded-full flex-shrink-0${isCurrent ? ' status-dot-current' : ''}`}
        style={{ backgroundColor: `var(${meta.dotVar})` }}
      />
      {meta.label}
    </span>
  );
}

export function StageBadge({ stage }) {
  const meta = STAGE[stage] || { label: stage || '?', badge: 'badge-neutral' };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded font-bold uppercase tracking-wider border ${meta.badge}`} style={{ fontSize: '0.65rem' }}>
      {meta.label}
    </span>
  );
}
