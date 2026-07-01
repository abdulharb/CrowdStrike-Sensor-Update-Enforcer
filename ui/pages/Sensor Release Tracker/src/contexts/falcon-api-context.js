import FalconApi from '@crowdstrike/foundry-js';
import { createContext, useEffect, useMemo, useState } from 'react';

const FalconApiContext = createContext(null);

function useFalconApiContext() {
  const [isInitialized, setIsInitialized] = useState(false);
  const falcon = useMemo(() => new FalconApi(), []);
  // isInitialized (React state) is the reactive dep — falcon.isConnected is a
  // plain property and won't trigger recomputation on its own.
  const navigation = useMemo(() => (isInitialized ? falcon.navigation : undefined), [isInitialized, falcon]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      // connect() never resolves outside the Falcon console — the timeout lets
      // a plain-browser preview render (Home falls back to sample data).
      await Promise.race([
        falcon.connect(),
        new Promise((resolve) => setTimeout(resolve, 3000)),
      ]);
      if (!cancelled) setIsInitialized(true);
    })();
    return () => { cancelled = true; };
  }, [falcon]);

  return { falcon, navigation, isInitialized };
}

export { useFalconApiContext, FalconApiContext };