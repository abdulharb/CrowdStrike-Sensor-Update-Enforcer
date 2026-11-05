import { STANDING } from '../lib/constants';
import { formatDate } from '../lib/format';

// Staircase of standings: steps descend top-left → bottom-right and fill the
// row width. `timeline` comes from standingTimeline() in lib/format.
export function StandingHistory({ timeline }) {
  const numSteps = Math.max(timeline.length - 1, 1);
  const maxPct = 65; // last step starts at 65% — leaves room for card content
  const stepPct = maxPct / numSteps;

  return (
    <div>
      <div className="type-xs text-body-and-labels mb-3 font-medium uppercase tracking-wider">Standing History</div>
      <div className="flex flex-col">
        {timeline.map((entry, idx) => {
          const meta = STANDING[entry.standing] || STANDING.untagged;
          const pct = (idx / numSteps) * maxPct;
          const prevPct = ((idx - 1) / numSteps) * maxPct;
          return (
            <div key={idx}>
              {/* L-shaped connector (riser) */}
              {idx > 0 && (
                <div
                  style={{
                    marginLeft: `calc(${prevPct}% + 10px)`,
                    width: `calc(${stepPct}% - 10px)`,
                    height: '10px',
                    borderLeft: '1.5px solid var(--border-faint)',
                    borderBottom: '1.5px solid var(--border-faint)',
                    borderBottomLeftRadius: '4px',
                  }}
                />
              )}
              {/* Step card */}
              <div
                className={`inline-flex items-center gap-2 px-3 py-1.5 rounded bg-surface-md border ${
                  entry.isCurrent ? 'border-border-reg' : 'border-border-faint'
                }`}
                style={{ marginLeft: `${pct}%` }}
              >
                <span
                  className="w-2 h-2 rounded-full flex-shrink-0"
                  style={{ backgroundColor: `var(${meta.dotVar})`, opacity: entry.isCurrent ? 1 : 0.5 }}
                />
                <span className={`text-xs ${entry.isCurrent ? 'font-semibold text-titles-and-attributes' : 'font-medium text-body-and-labels'}`}>
                  {meta.label}
                  {entry.isCurrent && <span className="opacity-60 ml-1" style={{ fontSize: '0.6rem' }}>now</span>}
                </span>
                {entry.timestamp && (
                  <span className="type-xs text-disabled tabular-nums whitespace-nowrap">
                    {formatDate(entry.timestamp)}
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
