// Inline SVG icons (avoids CSP issues with the Shoelace icon CDN).

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

export { IconRefresh, IconSearch, IconX, IconWarning, IconChevron, IconCopy, IconCheck, IconSort };
