export function relativeTime(ts) {
  if (!ts) return '';
  const sec = Math.floor(Date.now() / 1000 - ts);
  if (sec < 60)    return 'just now';
  if (sec < 3600)  return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  const days = Math.floor(sec / 86400);
  if (days < 30)   return `${days}d ago`;
  return `${Math.floor(days / 30)}mo ago`;
}

export function formatDate(ts) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleString(undefined, {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

// Splits "7.32.20403" into numeric parts so 7.9 < 7.10 sorts correctly
export function compareVersions(a, b) {
  const ap = String(a).split('.').map(Number);
  const bp = String(b).split('.').map(Number);
  for (let i = 0; i < Math.max(ap.length, bp.length); i++) {
    const diff = (ap[i] ?? 0) - (bp[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

// The standing history of a record, oldest first, ending with the current
// standing. Consecutive duplicate standings in previous_standings are
// collapsed. A record that never changed standing yields a single entry.
export function standingTimeline(row) {
  const history = Array.isArray(row.previous_standings) ? row.previous_standings : [];
  const past = history
    .filter((entry, idx) => idx === 0 || entry.standing !== history[idx - 1].standing)
    .map((h) => ({ standing: h.standing, timestamp: h.timestamp, isCurrent: false }));
  return [
    ...past,
    {
      standing: row.release_standing,
      timestamp: row.standing_updated_timestamp || row.first_seen_timestamp,
      isCurrent: true,
    },
  ];
}
