import { STANDING } from '../lib/constants';
import { StageBadge } from './badges';

// One platform: current N hero, N-1/N-2 trail. Clicking toggles the platform filter.
export function PlatformCard({ label, stat, isActive, onToggle }) {
  const trail = [['n-1', stat.n1], ['n-2', stat.n2]];
  return (
    <div
      className={`bg-surface-md border rounded-lg p-5 cursor-pointer transition-colors hover:bg-surface-lg ${
        isActive ? 'border-border-reg' : 'border-border-faint'
      }`}
      style={isActive ? { boxShadow: '0 0 0 1px var(--informational)' } : {}}
      onClick={onToggle}
      role="button"
      tabIndex={0}
      aria-pressed={isActive}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault(); // Space would scroll the page otherwise
          onToggle();
        }
      }}
    >
      {/* Header: platform · build count */}
      <div className="flex items-baseline gap-2 mb-3 min-w-0">
        <span className="type-sm font-semibold text-titles-and-attributes">{label}</span>
        <span className="type-xs text-disabled tabular-nums whitespace-nowrap">
          {stat.count} build{stat.count !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Hero: current N version */}
      <div className="flex items-center gap-1.5 mb-1">
        <span className="w-1.5 h-1.5 rounded-full status-dot-current" style={{ backgroundColor: 'var(--informational)' }} />
        <span className="uppercase tracking-wider text-body-and-labels font-medium" style={{ fontSize: '0.6rem' }}>
          Current · N
        </span>
      </div>
      {stat.n ? (
        <div className="flex items-baseline gap-2 flex-wrap">
          <span className="type-sm-mono tabular-nums text-text-and-icons" style={{ fontSize: '1.5rem', lineHeight: 1.1 }}>
            {stat.n.sensor_version}
          </span>
          {stat.n_ea && (
            <span className="inline-flex items-baseline gap-1.5 text-body-and-labels">
              <span className="type-sm-mono tabular-nums">{stat.n_ea.sensor_version}</span>
              <StageBadge stage="early_adopter" />
            </span>
          )}
        </div>
      ) : (
        <span className="type-sm text-disabled italic">No current build</span>
      )}

      {/* Trail: N-1 / N-2 */}
      <div className="grid grid-cols-2 gap-3 mt-4 pt-3 border-t border-border-faint">
        {trail.map(([standing, record]) => {
          const smeta = STANDING[standing];
          return (
            <div key={standing}>
              <div className="flex items-center gap-1.5 mb-0.5">
                <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: `var(${smeta.dotVar})` }} />
                <span className="type-xs text-body-and-labels font-medium">{smeta.label}</span>
              </div>
              {record ? (
                <span className="type-sm-mono tabular-nums text-titles-and-attributes">{record.sensor_version}</span>
              ) : (
                <span className="type-sm text-disabled italic">—</span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
