export const COLLECTION_NAME = 'sensor_release_tracker';

// foundry-js list() caps at this many keys; the UI warns when the cap is hit.
export const MAX_RECORDS = 500;

export const PLATFORM = {
  mac:     { label: 'macOS' },
  windows: { label: 'Windows' },
  linux:   { label: 'Linux' },
};

// Severity ramp: the further from current, the more the enforcer cares.
// N (current) → blue, N-1 (supported) → green, N-2 (aging) → amber,
// untagged (out of support / force-update target) → red.
export const STANDING = {
  'n':        { label: 'N',        badge: 'badge-informational', dotVar: '--informational' },
  'n-1':      { label: 'N-1',      badge: 'badge-positive',      dotVar: '--positive' },
  'n-2':      { label: 'N-2',      badge: 'badge-medium',        dotVar: '--medium' },
  'untagged': { label: 'Untagged', badge: 'badge-high',          dotVar: '--high' },
};

export const STAGE = {
  prod:          { label: 'Prod', badge: 'badge-informational' },
  early_adopter: { label: 'EA',   badge: 'badge-purple' },
};

const now = Date.now() / 1000;

// Shown (behind a banner) when the page runs outside the Falcon console.
export const MOCK_DATA = [
  { platform: 'windows', sensor_version: '7.32.20403',  release_standing: 'n',        build_number: '20403', stage: 'prod',          first_seen_timestamp: now - 86400 },
  { platform: 'windows', sensor_version: '7.32.20407',  release_standing: 'n',        build_number: '20407', stage: 'early_adopter', first_seen_timestamp: now - 43200 },
  { platform: 'windows', sensor_version: '7.30.20103',  release_standing: 'n-1',      build_number: '20103', stage: 'prod',          first_seen_timestamp: now - 864000,
    standing_updated_timestamp: now - 86400, previous_standings: [{ standing: 'n', timestamp: now - 864000 }] },
  { platform: 'windows', sensor_version: '7.28.19500',  release_standing: 'n-2',      build_number: '19500', stage: 'prod',          first_seen_timestamp: now - 2592000,
    standing_updated_timestamp: now - 86400, previous_standings: [{ standing: 'n', timestamp: now - 2592000 }, { standing: 'n-1', timestamp: now - 864000 }] },
  { platform: 'windows', sensor_version: '7.26.18900',  release_standing: 'untagged', build_number: '18900', stage: 'prod',          first_seen_timestamp: now - 5184000,
    standing_updated_timestamp: now - 86400, previous_standings: [{ standing: 'n', timestamp: now - 5184000 }, { standing: 'n-1', timestamp: now - 2592000 }, { standing: 'n-2', timestamp: now - 864000 }] },
  { platform: 'mac',     sensor_version: '7.32.20401',  release_standing: 'n',        build_number: '20401', stage: 'prod',          first_seen_timestamp: now - 86400 },
  { platform: 'mac',     sensor_version: '7.32.20405',  release_standing: 'n',        build_number: '20405', stage: 'early_adopter', first_seen_timestamp: now - 21600 },
  { platform: 'mac',     sensor_version: '7.30.20100',  release_standing: 'n-1',      build_number: '20100', stage: 'prod',          first_seen_timestamp: now - 864000 },
  { platform: 'mac',     sensor_version: '7.28.19400',  release_standing: 'n-2',      build_number: '19400', stage: 'prod',          first_seen_timestamp: now - 2592000 },
  { platform: 'linux',   sensor_version: '7.32.20400',  release_standing: 'n',        build_number: '20400', stage: 'prod',          first_seen_timestamp: now - 172800 },
  { platform: 'linux',   sensor_version: '7.30.20098',  release_standing: 'n-1',      build_number: '20098', stage: 'prod',          first_seen_timestamp: now - 950400 },
  { platform: 'linux',   sensor_version: '7.28.19498',  release_standing: 'n-2',      build_number: '19498', stage: 'prod',          first_seen_timestamp: now - 2678400 },
];
