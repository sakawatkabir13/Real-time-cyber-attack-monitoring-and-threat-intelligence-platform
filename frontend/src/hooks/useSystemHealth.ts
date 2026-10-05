import { useEffect, useState } from 'react';

export interface SystemHealth {
  checks: { database: boolean; redis: boolean };
  background: { websocketRelay: boolean; windowScorer: boolean; incidentGrouping: boolean; celeryBeatWorker: boolean; collectorFresh: boolean; modelState: string; modelFresh: boolean | null };
}
export function useSystemHealth() {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [checkedAt, setCheckedAt] = useState<string | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  useEffect(() => {
    let cancelled = false;
    const refresh = async () => {
      try {
        const response = await fetch('/api/health', { signal: AbortSignal.timeout(10000) });
        const data = await response.json() as SystemHealth;
        if (!data.checks || !data.background) throw new Error('Invalid health response');
        if (!cancelled) { setHealth(data); setUnavailable(false); setCheckedAt(new Date().toISOString()); }
      } catch { if (!cancelled) setUnavailable(true); }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 30000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, []);
  return { health, checkedAt, unavailable };
}
