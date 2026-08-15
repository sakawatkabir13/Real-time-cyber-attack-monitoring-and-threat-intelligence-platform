import { useEffect } from 'react';

import { useAppStore } from '@/store/appStore';


export default function AlertSync() {
  const loadAlerts = useAppStore((state) => state.loadAlerts);

  useEffect(() => {
    void loadAlerts();
  }, [loadAlerts]);

  return null;
}
