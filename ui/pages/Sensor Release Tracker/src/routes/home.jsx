import React, { useContext, useEffect, useState, useMemo, useCallback } from "react";
import { FalconApiContext } from "../contexts/falcon-api-context";
import '@shoelace-style/shoelace/dist/components/spinner/spinner.js';
import '@shoelace-style/shoelace/dist/components/alert/alert.js';
import { SlSpinner, SlAlert } from '@shoelace-style/shoelace/dist/react';

// ─── Inline SVG Icons (avoids CSP issues with Shoelace icon CDN) ─

function IconRefresh({ size = 14, className = '' }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 8A6 6 0 1 1 8 2" /><path d="M14 2v4h-4" />
    </svg>
  );
}

function IconSearch({ size = 14, className = '' }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
      <circle cx="6.5" cy="6.5" r="4.5" /><path d="M10 10l4 4" />
    </svg>
  );
}

function IconX({ size = 14, className = '' }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
      <path d="M4 4l8 8M12 4l-8 8" />
    </svg>
  );
}

function IconWarning({ size = 16, className = '' }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 16 16" fill="currentColor">
      <path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566zM8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5zm.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2z"/>
    </svg>
  );
}

function IconChevron({ size = 12, expanded = false, className = '' }) {
  return (
    <svg
      className={className}
      style={{ transform: expanded ? 'rotate(90deg)' : 'rotate(0deg)', transition: 'transform 150ms ease' }}
      width={size} height={size} viewBox="0 0 16 16" fill="none"
      stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
    >
      <path d="M6 4l4 4-4 4" />
    </svg>
  );
}

function IconCopy({ size = 14, className = '' }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <rect x="5" y="5" width="9" height="9" rx="1.5" /><path d="M5 11H3.5A1.5 1.5 0 012 9.5v-7A1.5 1.5 0 013.5 1h7A1.5 1.5 0 0112 2.5V5" />
    </svg>
  );
}

function IconCheck({ size = 14, className = '' }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 8.5l3.5 3.5 6.5-7" />
    </svg>
  );
}

// Up/down triangles — dim the inactive direction, brighten the active one
function IconSort({ size = 9, direction = null, className = '' }) {
  return (
    <svg
      className={className}
      width={size} height={Math.round(size * 1.6)}
      viewBox="0 0 10 16"
      fill="currentColor"
      aria-hidden="true"
      style={{ flexShrink: 0 }}
    >
      <path d="M5 1L9 6H1z" style={{ opacity: direction === 'asc' ? 1 : 0.3 }} />
      <path d="M5 15L1 10H9z" style={{ opacity: direction === 'desc' ? 1 : 0.3 }} />
    </svg>
  );
}

// ─── Configuration ───────────────────────────────────────────────

const PLATFORM = {
  mac:     { label: 'macOS' },
  windows: { label: 'Windows' },
  linux:   { label: 'Linux' },
};

const STANDING = {
  'n':        { label: 'N',        badge: 'badge-informational', dotVar: '--informational' },
  'n-1':      { label: 'N-1',      badge: 'badge-positive',      dotVar: '--positive' },
  'n-2':      { label: 'N-2',      badge: 'badge-purple',        dotVar: '--purple' },
  'untagged': { label: 'Untagged', badge: 'badge-neutral',       dotVar: '--disabled' },
};

const STAGE = {
  prod:          { label: 'Prod', badge: 'badge-informational' },
  early_adopter: { label: 'EA',   badge: 'badge-purple' },
};

const MOCK_DATA = [
  { platform: 'windows', sensor_version: '7.32.20403',  release_standing: 'n',        build_number: '20403', stage: 'prod',          first_seen_timestamp: Date.now() / 1000 - 86400 },
  { platform: 'windows', sensor_version: '7.32.20407',  release_standing: 'n',        build_number: '20407', stage: 'early_adopter', first_seen_timestamp: Date.now() / 1000 - 43200 },
  { platform: 'windows', sensor_version: '7.30.20103',  release_standing: 'n-1',      build_number: '20103', stage: 'prod',          first_seen_timestamp: Date.now() / 1000 - 864000 },
  { platform: 'windows', sensor_version: '7.28.19500',  release_standing: 'n-2',      build_number: '19500', stage: 'prod',          first_seen_timestamp: Date.now() / 1000 - 2592000 },
  { platform: 'windows', sensor_version: '7.26.18900',  release_standing: 'untagged', build_number: '18900', stage: 'prod',          first_seen_timestamp: Date.now() / 1000 - 5184000 },
  { platform: 'mac',     sensor_version: '7.32.20401',  release_standing: 'n',        build_number: '20401', stage: 'prod',          first_seen_timestamp: Date.now() / 1000 - 86400 },
  { platform: 'mac',     sensor_version: '7.32.20405',  release_standing: 'n',        build_number: '20405', stage: 'early_adopter', first_seen_timestamp: Date.now() / 1000 - 21600 },
  { platform: 'mac',     sensor_version: '7.30.20100',  release_standing: 'n-1',      build_number: '20100', stage: 'prod',          first_seen_timestamp: Date.now() / 1000 - 864000 },
  { platform: 'mac',     sensor_version: '7.28.19400',  release_standing: 'n-2',      build_number: '19400', stage: 'prod',          first_seen_timestamp: Date.now() / 1000 - 2592000 },
  { platform: 'linux',   sensor_version: '7.32.20400',  release_standing: 'n',        build_number: '20400', stage: 'prod',          first_seen_timestamp: Date.now() / 1000 - 172800 },
  { platform: 'linux',   sensor_version: '7.30.20098',  release_standing: 'n-1',      build_number: '20098', stage: 'prod',          first_seen_timestamp: Date.now() / 1000 - 950400 },
  { platform: 'linux',   sensor_version: '7.28.19498',  release_standing: 'n-2',      build_number: '19498', stage: 'prod',          first_seen_timestamp: Date.now() / 1000 - 2678400 },
];

// ─── Helpers ─────────────────────────────────────────────────────

function relativeTime(ts) {
  if (!ts) return '';
  const sec = Math.floor(Date.now() / 1000 - ts);
  if (sec < 60)    return 'just now';
  if (sec < 3600)  return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  const days = Math.floor(sec / 86400);
  if (days < 30)   return `${days}d ago`;
  return `${Math.floor(days / 30)}mo ago`;
}

function formatDate(ts) {
  if (!ts) return '\u2014';
  return new Date(ts * 1000).toLocaleString(undefined, {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

// ─── Sub-components ──────────────────────────────────────────────

function PlatformBadge({ platform }) {
  const key = platform?.toLowerCase();
  const meta = PLATFORM[key] || { label: platform || 'Unknown' };
  return (
    <span className="inline-flex items-center px-2.5 py-1 rounded text-xs font-medium bg-surface-lg text-titles-and-attributes border border-border-faint">
      {meta.label}
    </span>
  );
}

function StandingBadge({ standing }) {
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

function StageBadge({ stage }) {
  const meta = STAGE[stage] || { label: stage || '?', badge: 'badge-neutral' };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded font-bold uppercase tracking-wider border ${meta.badge}`} style={{ fontSize: '0.65rem' }}>
      {meta.label}
    </span>
  );
}

function FilterPills({ label, options, value, onChange }) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-body-and-labels font-medium uppercase tracking-wider" style={{ fontSize: '0.65rem' }}>{label}</span>
      <div className="flex gap-1">
        {options.map((opt) => (
          <button
            key={opt.value}
            onClick={() => onChange(opt.value)}
            className={`focusable rounded px-2.5 py-1.5 text-xs font-medium transition-colors ${
              value === opt.value ? 'interactive-primary' : 'interactive-quiet'
            }`}
          >
            {opt.label}
          </button>
        ))}
      </div>
    </div>
  );
}

// ─── Version sort helper ─────────────────────────────────────────
// Splits "7.32.20403" into numeric parts so 7.9 < 7.10 sorts correctly
function compareVersions(a, b) {
  const ap = String(a).split('.').map(Number);
  const bp = String(b).split('.').map(Number);
  for (let i = 0; i < Math.max(ap.length, bp.length); i++) {
    const diff = (ap[i] ?? 0) - (bp[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

// ─── Main Component ──────────────────────────────────────────────

function Home() {
  const { falcon, isInitialized } = useContext(FalconApiContext);
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [exportStatus, setExportStatus] = useState('idle');

  // Filters
  const [platformFilter, setPlatformFilter] = useState('all');
  const [standingFilter, setStandingFilter] = useState('all');
  const [stageFilter, setStageFilter] = useState('all');
  const [search, setSearch] = useState('');

  // Sort
  const [sortConfig, setSortConfig] = useState({ key: 'sensor_version', direction: 'desc' });

  // Expanded rows (by row key)
  const [expandedRows, setExpandedRows] = useState(new Set());

  const toggleRow = useCallback((key) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  // ── Data fetching ──────────────────────────────────────
  const fetchData = useCallback(async (isRefresh = false) => {
    try {
      if (isRefresh) setRefreshing(true);
      else setLoading(true);
      setError(null);

      if (!falcon.isConnected) {
        console.log('Falcon not connected — using mock data for preview.');
        setData(MOCK_DATA);
        setLastUpdated(new Date());
        return;
      }

      const col = falcon.collection({ collection: 'sensor_release_tracker' });
      const keysRes = await col.list({ limit: 500 });
      const keys = keysRes.resources || [];
      if (keys.length >= 500) console.warn('Collection may have more than 500 records — only first 500 shown.');

      if (keys.length === 0) {
        setData([]);
        setLastUpdated(new Date());
        return;
      }

      const records = await Promise.all(
        keys.map(async (key) => {
          try { return await col.read(key); }
          catch (e) { console.warn(`Read failed for ${key}:`, e); return null; }
        })
      );

      setData(records.filter(Boolean));
      setLastUpdated(new Date());
    } catch (err) {
      console.error('Collection fetch error:', err);
      setError('Unable to load sensor data. Make sure this is running inside the Falcon Console.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [falcon]);

  useEffect(() => {
    if (falcon && isInitialized) fetchData();
  }, [falcon, isInitialized, fetchData]);

  // ── Export collection as JSON ──────────────────────────
  // Foundry's sandboxed iframe blocks downloads AND popups.
  // Copy to clipboard as the reliable fallback.
  const exportJson = useCallback(async () => {
    const json = JSON.stringify(data, null, 2);

    try {
      await navigator.clipboard.writeText(json);
      setExportStatus('copied');
      setTimeout(() => setExportStatus('idle'), 3000);
    } catch (e) {
      console.error('Clipboard write failed:', e);
      setExportStatus('failed');
      setTimeout(() => setExportStatus('idle'), 3000);
    }
  }, [data]);

  // ── Sort handler ───────────────────────────────────────
  const handleSort = useCallback((key) => {
    setSortConfig((prev) => ({
      key,
      direction: prev.key === key && prev.direction === 'asc' ? 'desc' : 'asc',
    }));
  }, []);

  // ── Filtered + sorted data ─────────────────────────────
  const processedData = useMemo(() => {
    let result = [...data];

    if (platformFilter !== 'all') result = result.filter((d) => d.platform?.toLowerCase() === platformFilter);
    if (standingFilter !== 'all') result = result.filter((d) => d.release_standing === standingFilter);
    if (stageFilter !== 'all')    result = result.filter((d) => d.stage === stageFilter);
    if (search) {
      const q = search.toLowerCase();
      result = result.filter((d) =>
        d.sensor_version?.toLowerCase().includes(q) ||
        d.build_number?.toLowerCase().includes(q) ||
        d.platform?.toLowerCase().includes(q)
      );
    }

    result.sort((a, b) => {
      const dir = sortConfig.direction === 'asc' ? 1 : -1;
      const av = a[sortConfig.key] ?? '';
      const bv = b[sortConfig.key] ?? '';
      if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * dir;
      if (sortConfig.key === 'sensor_version' || sortConfig.key === 'build_number') {
        return compareVersions(av, bv) * dir;
      }
      return String(av).localeCompare(String(bv)) * dir;
    });

    return result;
  }, [data, platformFilter, standingFilter, stageFilter, search, sortConfig]);

  // ── Platform stats ─────────────────────────────────────
  const platformStats = useMemo(() => {
    const result = {};
    for (const key of Object.keys(PLATFORM)) {
      const items = data.filter((d) => d.platform?.toLowerCase() === key);
      const byStanding = (s) =>
        items.find((d) => d.release_standing === s && d.stage === 'prod') ||
        items.find((d) => d.release_standing === s);
      const nRecord = byStanding('n');
      const nEa = items.find((d) => d.release_standing === 'n' && d.stage === 'early_adopter');
      result[key] = {
        count: items.length,
        n:    nRecord,
        n1:   byStanding('n-1'),
        n2:   byStanding('n-2'),
        // Only set n_ea if it's a different object than the primary N record
        n_ea: nEa && nEa !== nRecord ? nEa : null,
      };
    }
    return result;
  }, [data]);

  // ── Dynamic filter options ─────────────────────────────
  const availableStandings = useMemo(
    () => [...new Set(data.map((d) => d.release_standing).filter(Boolean))].sort(),
    [data]
  );
  const availableStages = useMemo(
    () => [...new Set(data.map((d) => d.stage).filter(Boolean))],
    [data]
  );

  const hasActiveFilters = platformFilter !== 'all' || standingFilter !== 'all' || stageFilter !== 'all' || search;

  const clearFilters = () => {
    setPlatformFilter('all');
    setStandingFilter('all');
    setStageFilter('all');
    setSearch('');
  };

  // ── Render helpers ─────────────────────────────────────
  const thBase = 'sticky top-0 z-10 bg-surface-inner py-3 px-5 font-medium text-body-and-labels uppercase tracking-wider text-xs cursor-pointer select-none hover:text-titles-and-attributes transition-colors border-b border-lines-dark';

  const sortIndicator = (key) => (
    <IconSort
      size={9}
      direction={sortConfig.key === key ? sortConfig.direction : null}
      className="ml-0.5"
    />
  );

  // ── Render ─────────────────────────────────────────────
  return (
    <div className="min-h-screen p-6 text-text-and-icons">
      <div className="max-w-7xl mx-auto space-y-5">

        {/* ── Header ── */}
        <header className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="type-xl text-text-and-icons">Sensor Release Tracker</h1>
            <p className="type-sm text-body-and-labels mt-0.5">
              Sensor versions and release standings across your CrowdStrike environment
            </p>
          </div>
          <div className="flex items-center gap-3 flex-shrink-0">
            {lastUpdated && (
              <span className="type-xs text-body-and-labels tabular-nums">
                Synced {lastUpdated.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </span>
            )}
            <button
              onClick={exportJson}
              disabled={data.length === 0 || exportStatus !== 'idle'}
              className={`focusable interactive-normal rounded px-3 py-1.5 type-xs inline-flex items-center gap-2 ${data.length === 0 || exportStatus !== 'idle' ? 'interactive-disabled' : ''}`}
              title="Copy collection JSON to clipboard"
            >
              {exportStatus === 'copied' ? <IconCheck /> : <IconCopy />}
              {exportStatus === 'copied' ? 'Copied to clipboard!' : exportStatus === 'failed' ? 'Copy failed' : 'Copy JSON'}
            </button>
            <button
              onClick={() => fetchData(true)}
              disabled={refreshing}
              className={`focusable interactive-normal rounded px-3 py-1.5 type-xs inline-flex items-center gap-2 ${refreshing ? 'interactive-disabled' : ''}`}
            >
              <span className={`inline-flex ${refreshing ? 'animate-spin' : ''}`}>
                <IconRefresh />
              </span>
              {refreshing ? 'Syncing…' : 'Refresh'}
            </button>
          </div>
        </header>

        {/* ── Content area ── */}
        {loading ? (
          <div className="flex flex-col justify-center items-center min-h-[40vh] gap-4">
            <SlSpinner style={{ fontSize: '3rem', '--track-width': '5px', color: 'var(--primary-idle)' }} />
            <p className="type-sm text-body-and-labels">Loading sensor data…</p>
          </div>
        ) : error ? (
          <div className="max-w-xl mx-auto pt-8">
            <SlAlert variant="danger" open>
              <span slot="icon"><IconWarning size={18} /></span>
              <div>
                <strong className="block mb-1">Failed to load data</strong>
                <span className="type-sm">{error}</span>
              </div>
            </SlAlert>
            <button
              onClick={() => fetchData()}
              className="focusable interactive-primary rounded px-4 py-2 type-sm mt-4"
            >
              Try Again
            </button>
          </div>
        ) : (
          <>
            {/* ── Platform Cards — click to filter by platform ── */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {Object.entries(PLATFORM).map(([key, meta]) => {
                const stat = platformStats[key] || { count: 0 };
                const isActive = platformFilter === key;
                const rows = [
                  { standing: 'n',   record: stat.n,  ea: stat.n_ea },
                  { standing: 'n-1', record: stat.n1, ea: null },
                  { standing: 'n-2', record: stat.n2, ea: null },
                ];
                return (
                  <div
                    key={key}
                    className={`bg-surface-md border rounded-lg p-5 cursor-pointer transition-colors hover:bg-surface-lg ${
                      isActive ? 'border-border-reg' : 'border-border-faint'
                    }`}
                    style={isActive ? { boxShadow: '0 0 0 1px var(--informational)' } : {}}
                    onClick={() => setPlatformFilter(isActive ? 'all' : key)}
                    role="button"
                    tabIndex={0}
                    aria-pressed={isActive}
                    onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && setPlatformFilter(isActive ? 'all' : key)}
                  >
                    <div className="flex items-center justify-between mb-4">
                      <span className="type-sm font-semibold text-titles-and-attributes">{meta.label}</span>
                      <span className="type-xs text-body-and-labels tabular-nums">
                        {stat.count} build{stat.count !== 1 ? 's' : ''}
                      </span>
                    </div>
                    <div className="space-y-2.5">
                      {rows.map(({ standing, record, ea }) => {
                        const smeta = STANDING[standing];
                        return (
                          <div key={standing} className="flex flex-col gap-1">
                            <div className="flex items-center justify-between gap-3">
                              <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border ${smeta.badge}`} style={{ minWidth: '3rem' }}>
                                {smeta.label}
                              </span>
                              {record ? (
                                <span className="type-sm-mono text-text-and-icons truncate flex-1 text-right">
                                  {record.sensor_version}
                                </span>
                              ) : (
                                <span className="type-xs text-disabled italic flex-1 text-right">—</span>
                              )}
                            </div>
                            {ea && (
                              <div className="flex items-center justify-end gap-1.5 pl-8">
                                <span className="type-sm-mono text-body-and-labels">{ea.sensor_version}</span>
                                <StageBadge stage="early_adopter" />
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* ── Filters ── */}
            <div className="bg-surface-md border border-border-faint rounded-lg p-4">
              <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
                <FilterPills
                  label="Platform"
                  value={platformFilter}
                  onChange={setPlatformFilter}
                  options={[
                    { value: 'all', label: 'All' },
                    ...Object.entries(PLATFORM).map(([k, v]) => ({ value: k, label: v.label })),
                  ]}
                />

                <FilterPills
                  label="Standing"
                  value={standingFilter}
                  onChange={setStandingFilter}
                  options={[
                    { value: 'all', label: 'All' },
                    ...availableStandings.map((s) => ({ value: s, label: STANDING[s]?.label || s })),
                  ]}
                />

                <FilterPills
                  label="Stage"
                  value={stageFilter}
                  onChange={setStageFilter}
                  options={[
                    { value: 'all', label: 'All' },
                    ...availableStages.map((s) => ({ value: s, label: STAGE[s]?.label || s })),
                  ]}
                />

                {/* Search */}
                <div className="flex-1 min-w-[180px]">
                  <div className="relative">
                    <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-disabled pointer-events-none">
                      <IconSearch />
                    </span>
                    <input
                      type="text"
                      placeholder="Search versions, builds…"
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      className="textbox type-sm w-full"
                      style={{ paddingLeft: '2.25rem', paddingRight: '2rem' }}
                    />
                    {search && (
                      <button
                        onClick={() => setSearch('')}
                        className="absolute inset-y-0 right-0 pr-3 flex items-center text-disabled hover:text-body-and-labels transition-colors"
                      >
                        <IconX />
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* ── Data Table ── */}
            <div className="bg-surface-base border border-border-faint rounded-lg overflow-hidden shadow-base">
              {/* Toolbar */}
              <div className="flex items-center justify-between px-5 py-3 border-b border-lines-dark bg-surface-md">
                <span className="type-xs text-body-and-labels">
                  Showing{' '}
                  <span className="text-titles-and-attributes font-semibold">{processedData.length}</span>
                  {processedData.length !== data.length && (
                    <> of <span className="text-titles-and-attributes font-semibold">{data.length}</span></>
                  )}
                  {' '}record{data.length !== 1 ? 's' : ''}
                </span>
                <span className="type-xs" style={{ minWidth: '6rem', textAlign: 'right' }}>
                  {hasActiveFilters ? (
                    <button onClick={clearFilters} className="interactive-link font-medium">
                      Clear all filters
                    </button>
                  ) : (
                    <span className="invisible">Clear all filters</span>
                  )}
                </span>
              </div>

              {/* Scrollable table */}
              <div className="overflow-x-auto max-h-[55vh] overflow-y-auto tracker-scroll">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr>
                      <th className={`${thBase} w-8`} />
                      <th
                        className={thBase}
                        onClick={() => handleSort('platform')}
                        tabIndex={0}
                        onKeyDown={(e) => e.key === 'Enter' && handleSort('platform')}
                        aria-label={`Sort by platform${sortConfig.key === 'platform' ? `, ${sortConfig.direction}ending` : ''}`}
                      >
                        <span className="inline-flex items-center gap-1">Platform{sortIndicator('platform')}</span>
                      </th>
                      <th
                        className={thBase}
                        onClick={() => handleSort('sensor_version')}
                        tabIndex={0}
                        onKeyDown={(e) => e.key === 'Enter' && handleSort('sensor_version')}
                        aria-label={`Sort by version${sortConfig.key === 'sensor_version' ? `, ${sortConfig.direction}ending` : ''}`}
                      >
                        <span className="inline-flex items-center gap-1">Version{sortIndicator('sensor_version')}</span>
                      </th>
                      <th
                        className={thBase}
                        onClick={() => handleSort('release_standing')}
                        tabIndex={0}
                        onKeyDown={(e) => e.key === 'Enter' && handleSort('release_standing')}
                        aria-label={`Sort by standing${sortConfig.key === 'release_standing' ? `, ${sortConfig.direction}ending` : ''}`}
                      >
                        <span className="inline-flex items-center gap-1">Standing{sortIndicator('release_standing')}</span>
                      </th>
                      <th
                        className={thBase}
                        onClick={() => handleSort('build_number')}
                        tabIndex={0}
                        onKeyDown={(e) => e.key === 'Enter' && handleSort('build_number')}
                        aria-label={`Sort by build${sortConfig.key === 'build_number' ? `, ${sortConfig.direction}ending` : ''}`}
                      >
                        <span className="inline-flex items-center gap-1">Build{sortIndicator('build_number')}</span>
                      </th>
                      <th
                        className={thBase}
                        onClick={() => handleSort('stage')}
                        tabIndex={0}
                        onKeyDown={(e) => e.key === 'Enter' && handleSort('stage')}
                        aria-label={`Sort by stage${sortConfig.key === 'stage' ? `, ${sortConfig.direction}ending` : ''}`}
                      >
                        <span className="inline-flex items-center gap-1">Stage{sortIndicator('stage')}</span>
                      </th>
                      <th
                        className={`${thBase} text-right`}
                        onClick={() => handleSort('first_seen_timestamp')}
                        tabIndex={0}
                        onKeyDown={(e) => e.key === 'Enter' && handleSort('first_seen_timestamp')}
                        aria-label={`Sort by first seen${sortConfig.key === 'first_seen_timestamp' ? `, ${sortConfig.direction}ending` : ''}`}
                      >
                        <span className="inline-flex items-center gap-1 justify-end">First Seen{sortIndicator('first_seen_timestamp')}</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {processedData.length === 0 ? (
                      <tr>
                        <td colSpan="7" className="py-16 text-center">
                          <div className="flex flex-col items-center gap-2">
                            <div className="type-sm text-body-and-labels font-medium">
                              {data.length > 0 ? 'No records match your filters' : 'No sensor data in the collection'}
                            </div>
                            {hasActiveFilters && (
                              <button onClick={clearFilters} className="interactive-link type-xs font-medium mt-1">
                                Clear filters
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ) : (
                      processedData.flatMap((row, i) => {
                        const rowKey = `${row.platform}_${row.build_number}` || String(i);
                        const isExpanded = expandedRows.has(rowKey);
                        const history = Array.isArray(row.previous_standings) ? row.previous_standings : [];
                        const cleanHistory = history.filter((entry, idx) => {
                          if (idx === 0) return true;
                          return entry.standing !== history[idx - 1].standing;
                        });
                        const hasHistory = cleanHistory.length > 0;

                        const mainRow = (
                          <tr key={rowKey} className={`border-b border-lines-dark hover:bg-surface-lg transition-colors${i % 2 === 1 ? ' bg-surface-inner' : ''}`}>
                            <td className="py-3 pl-4 pr-1 w-8">
                              {hasHistory ? (
                                <button
                                  onClick={() => toggleRow(rowKey)}
                                  className="focusable rounded p-0.5 text-disabled hover:text-body-and-labels transition-colors"
                                  title="Show standing history"
                                  aria-expanded={isExpanded}
                                  aria-label="Toggle standing history"
                                >
                                  <IconChevron expanded={isExpanded} />
                                </button>
                              ) : (
                                <span className="w-5 inline-block" />
                              )}
                            </td>
                            <td className="py-3 px-5">
                              <PlatformBadge platform={row.platform} />
                            </td>
                            <td className="py-3 px-5 type-sm-mono text-text-and-icons">
                              {row.sensor_version}
                            </td>
                            <td className="py-3 px-5">
                              <StandingBadge standing={row.release_standing} />
                            </td>
                            <td className="py-3 px-5 type-sm-mono text-body-and-labels">
                              {row.build_number}
                            </td>
                            <td className="py-3 px-5">
                              <StageBadge stage={row.stage} />
                            </td>
                            <td className="py-3 px-5 text-right">
                              {/* Relative time primary, absolute secondary */}
                              <div className="type-sm text-titles-and-attributes tabular-nums">{relativeTime(row.first_seen_timestamp)}</div>
                              <div className="type-xs text-disabled tabular-nums">{formatDate(row.first_seen_timestamp)}</div>
                            </td>
                          </tr>
                        );

                        if (!isExpanded || !hasHistory) return [mainRow];

                        const timeline = [
                          ...cleanHistory.map((h) => ({ standing: h.standing, timestamp: h.timestamp, isCurrent: false })),
                          { standing: row.release_standing, timestamp: row.standing_updated_timestamp || row.first_seen_timestamp, isCurrent: true },
                        ];

                        const historyRow = (
                          <tr key={`${rowKey}-history`} className="border-b border-lines-dark bg-surface-inner">
                            <td />
                            <td colSpan="6" className="py-3 px-5 pb-4">
                              <div className="type-xs text-body-and-labels mb-3 font-medium uppercase tracking-wider">Standing History</div>
                              {/* Staircase: fills the full row width, steps descend top-left → bottom-right */}
                              {(() => {
                                const numSteps = Math.max(timeline.length - 1, 1);
                                const maxPct = 65; // last step starts at 65% — leaves room for card content
                                return (
                                  <div className="flex flex-col">
                                    {timeline.map((entry, idx) => {
                                      const meta = STANDING[entry.standing] || STANDING.untagged;
                                      const pct = (idx / numSteps) * maxPct;
                                      const prevPct = ((idx - 1) / numSteps) * maxPct;
                                      const stepPct = maxPct / numSteps;
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
                                );
                              })()}
                            </td>
                          </tr>
                        );

                        return [mainRow, historyRow];
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export { Home };
