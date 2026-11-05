import { useCallback, useEffect, useState } from 'react';
import { COLLECTION_NAME, MAX_RECORDS, MOCK_DATA } from '../lib/constants';

// Read in small batches — a flat Promise.all over hundreds of keys trips the
// collection API rate limit and drops rows silently.
const READ_BATCH = 8;

async function readCollection(falcon) {
  const col = falcon.collection({ collection: COLLECTION_NAME });
  const keysRes = await col.list({ limit: MAX_RECORDS });
  if (keysRes?.errors?.length) {
    throw new Error(keysRes.errors[0]?.message || 'Collection list failed');
  }
  const keys = keysRes.resources || [];

  const records = [];
  for (let i = 0; i < keys.length; i += READ_BATCH) {
    const chunk = await Promise.all(
      keys.slice(i, i + READ_BATCH).map(async (key) => {
        try { return await col.read(key); }
        catch (e) { console.warn(`Read failed for ${key}:`, e); return null; }
      })
    );
    records.push(...chunk);
  }

  const valid = records.filter((r) => r && r.sensor_version);
  const warnings = [];
  const failedCount = keys.length - valid.length;
  if (failedCount > 0) warnings.push(`${failedCount} of ${keys.length} records failed to load`);
  if (keys.length >= MAX_RECORDS) warnings.push(`showing first ${MAX_RECORDS} records — collection may contain more`);
  return { data: valid, warning: warnings.length ? warnings.join('; ') : null };
}

// Loads the sensor_release_tracker collection once the Falcon API is ready.
// Outside the console (no connection) it serves MOCK_DATA and says so.
export function useSensorReleases(falcon, isInitialized) {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [loadWarning, setLoadWarning] = useState(null);
  const [usingMockData, setUsingMockData] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);

  const load = useCallback(async (isRefresh = false) => {
    try {
      if (isRefresh) setRefreshing(true);
      else setLoading(true);
      setError(null);
      setLoadWarning(null);

      if (!falcon.isConnected) {
        console.log('Falcon not connected — using mock data for preview.');
        setUsingMockData(true);
        setData(MOCK_DATA);
      } else {
        setUsingMockData(false);
        const result = await readCollection(falcon);
        setData(result.data);
        setLoadWarning(result.warning);
      }
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
    if (falcon && isInitialized) load();
  }, [falcon, isInitialized, load]);

  return {
    data, loading, refreshing, error, loadWarning, usingMockData, lastUpdated,
    reload: () => load(false),
    refresh: () => load(true),
  };
}
