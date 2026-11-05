import { useContext, useState, useMemo, useCallback } from "react";
import { FalconApiContext } from "../contexts/falcon-api-context";
import '@shoelace-style/shoelace/dist/components/spinner/spinner.js';
import '@shoelace-style/shoelace/dist/components/alert/alert.js';
import { SlSpinner, SlAlert } from '@shoelace-style/shoelace/dist/react';

import { PLATFORM, STANDING, STAGE } from '../lib/constants';
import { relativeTime, formatDate, compareVersions, standingTimeline } from '../lib/format';
import { useSensorReleases } from '../hooks/use-sensor-releases';
import { IconRefresh, IconSearch, IconX, IconWarning, IconChevron, IconCopy, IconCheck, IconSort } from '../components/icons';
import { PlatformBadge, StandingBadge, StageBadge } from '../components/badges';
import { PlatformCard } from '../components/platform-card';
import { StandingHistory } from '../components/standing-history';

// ─── Sub-components ──────────────────────────────────────────────

function FilterPills({ label, options, value, onChange }) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-body-and-labels font-medium uppercase tracking-wider" style={{ fontSize: '0.65rem' }}>{label}</span>
      <div className="flex gap-1">
        {options.map((opt) => (
          <button
            key={opt.value}
            onClick={() => onChange(opt.value)}
            aria-pressed={value === opt.value}
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

function SortableTh({ colKey, label, sortConfig, onSort, className, align }) {
  const active = sortConfig.key === colKey;
  return (
    <th
      className={className}
      onClick={() => onSort(colKey)}
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onSort(colKey);
        }
      }}
      aria-sort={active ? (sortConfig.direction === 'asc' ? 'ascending' : 'descending') : 'none'}
    >
      <span className={`inline-flex items-center gap-1${align === 'right' ? ' justify-end' : ''}`}>
        {label}
        <IconSort size={9} direction={active ? sortConfig.direction : null} className="ml-0.5" />
      </span>
    </th>
  );
}

// Foundry's sandboxed iframe blocks downloads AND popups, so "export" means
// copy to clipboard. The Clipboard API is often blocked in sandboxed
// cross-origin iframes too — fall back to the legacy execCommand path.
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    ta.remove();
    return ok;
  }
}

// ─── Main Component ──────────────────────────────────────────────

function Home() {
  const { falcon, isInitialized } = useContext(FalconApiContext);
  const {
    data, loading, refreshing, error, loadWarning, usingMockData, lastUpdated, reload, refresh,
  } = useSensorReleases(falcon, isInitialized);
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

  const exportJson = useCallback(async () => {
    const ok = await copyText(JSON.stringify(data, null, 2));
    setExportStatus(ok ? 'copied' : 'failed');
    setTimeout(() => setExportStatus('idle'), 3000);
  }, [data]);

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
  const exportDisabled = data.length === 0 || exportStatus !== 'idle';

  // ── Render ─────────────────────────────────────────────
  return (
    <div className="min-h-screen p-6 text-text-and-icons">
      <div className="max-w-7xl mx-auto space-y-5">

        {/* ── Header ── */}
        {/* flex-wrap instead of sm: variants — Toucan's prebuilt CSS has no
            responsive prefixes, so sm:/md: classes silently no-op. */}
        <header className="flex flex-wrap items-center justify-between gap-4">
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
              disabled={exportDisabled}
              className={`focusable interactive-normal rounded px-3 py-1.5 type-xs inline-flex items-center gap-2 ${exportDisabled ? 'interactive-disabled' : ''}`}
              title="Copy collection JSON to clipboard"
            >
              {exportStatus === 'copied' ? <IconCheck /> : <IconCopy />}
              {exportStatus === 'copied' ? 'Copied to clipboard!' : exportStatus === 'failed' ? 'Copy failed' : 'Copy JSON'}
            </button>
            <button
              onClick={refresh}
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

        {/* ── Preview-mode banner — never let sample data pass as live ── */}
        {usingMockData && !loading && (
          <div className="inline-flex items-center gap-2 px-3 py-2 rounded border badge-medium type-xs font-medium" role="status">
            <IconWarning size={14} />
            Preview mode — showing sample data. Open this page inside the Falcon console to see live records.
          </div>
        )}

        {/* ── Content area ── */}
        {loading ? (
          <div className="flex flex-col justify-center items-center gap-4" style={{ minHeight: '40vh' }}>
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
              onClick={reload}
              className="focusable interactive-primary rounded px-4 py-2 type-sm mt-4"
            >
              Try Again
            </button>
          </div>
        ) : (
          <>
            {/* ── Platform Cards — current N hero + N-1/N-2 trail + posture ── */}
            {/* Inline auto-fit grid: Toucan's prebuilt CSS has no `md:` variant,
                so responsive Tailwind prefixes no-op. This stays 3-up on desktop
                and wraps on narrow without depending on Toucan breakpoints. */}
            <div className="grid gap-4" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))' }}>
              {Object.entries(PLATFORM).map(([key, meta]) => {
                const isActive = platformFilter === key;
                return (
                  <PlatformCard
                    key={key}
                    label={meta.label}
                    stat={platformStats[key] || { count: 0 }}
                    isActive={isActive}
                    onToggle={() => setPlatformFilter(isActive ? 'all' : key)}
                  />
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
                <div className="flex-1" style={{ minWidth: '180px' }}>
                  <div className="relative">
                    <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-disabled pointer-events-none">
                      <IconSearch />
                    </span>
                    <input
                      type="text"
                      placeholder="Search versions, builds…"
                      aria-label="Search versions, builds, and platforms"
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      className="textbox type-sm w-full"
                      style={{ paddingLeft: '2.25rem', paddingRight: '2rem' }}
                    />
                    {search && (
                      <button
                        onClick={() => setSearch('')}
                        aria-label="Clear search"
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
                  {loadWarning && (
                    <span style={{ color: 'var(--medium)' }}> · {loadWarning}</span>
                  )}
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

              {/* Scrollable table — inline maxHeight: arbitrary-value classes
                  like max-h-[55vh] don't exist in the prebuilt Toucan CSS */}
              <div className="overflow-x-auto overflow-y-auto tracker-scroll" style={{ maxHeight: '55vh' }}>
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr>
                      <th className={`${thBase} w-8`} />
                      <SortableTh colKey="platform" label="Platform" sortConfig={sortConfig} onSort={handleSort} className={thBase} />
                      <SortableTh colKey="sensor_version" label="Version" sortConfig={sortConfig} onSort={handleSort} className={thBase} />
                      <SortableTh colKey="release_standing" label="Standing" sortConfig={sortConfig} onSort={handleSort} className={thBase} />
                      <SortableTh colKey="build_number" label="Build" sortConfig={sortConfig} onSort={handleSort} className={thBase} />
                      <SortableTh colKey="stage" label="Stage" sortConfig={sortConfig} onSort={handleSort} className={thBase} />
                      <SortableTh colKey="first_seen_timestamp" label="First Seen" sortConfig={sortConfig} onSort={handleSort} className={`${thBase} text-right`} align="right" />
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
                        // stage disambiguates a build present in both prod and EA
                        const rowKey = `${row.platform}_${row.build_number}_${row.stage || i}`;
                        const isExpanded = expandedRows.has(rowKey);
                        const timeline = standingTimeline(row);
                        const hasHistory = timeline.length > 1;

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

                        const historyRow = (
                          <tr key={`${rowKey}-history`} className="border-b border-lines-dark bg-surface-inner">
                            <td />
                            <td colSpan="6" className="py-3 px-5 pb-4">
                              <StandingHistory timeline={timeline} />
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
