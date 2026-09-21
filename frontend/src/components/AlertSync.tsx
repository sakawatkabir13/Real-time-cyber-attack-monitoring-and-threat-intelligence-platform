import { useEffect } from 'react';

import { useAppStore } from '@/store/appStore';


export default function AlertSync() {
  const loadAlerts = useAppStore((state) => state.loadAlerts);
  const autoRefresh = useAppStore((state) => state.settings.autoRefresh);

  useEffect(() => {
    void loadAlerts();
    const timer = autoRefresh ? window.setInterval(() => void loadAlerts(), 30000) : null;
    return () => { if (timer !== null) window.clearInterval(timer); };
  }, [loadAlerts, autoRefresh]);

  return null;
}
