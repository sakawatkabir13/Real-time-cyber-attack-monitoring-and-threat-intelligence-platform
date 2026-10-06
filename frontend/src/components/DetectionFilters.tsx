import { useEffect, useState } from 'react';
import { useDetectionViewStore, type DetectionPeriod } from '@/store/detectionViewStore';

export default function DetectionFilters() {
  const { hours, serverId, setHours, setServerId } = useDetectionViewStore();
  const [servers, setServers] = useState<string[]>([]);
  useEffect(() => {
    let cancelled = false;
    const syncFilters = (event: StorageEvent) => {
      if (event.key === 'vanguard-detection-view') void useDetectionViewStore.persist.rehydrate();
    };
    window.addEventListener('storage', syncFilters);
    fetch('/api/collectors').then((response) => response.ok ? response.json() : [])
      .then((rows: Array<{ serverId: string }>) => {
        if (!cancelled) setServers([...new Set(rows.map((row) => row.serverId))].sort());
      }).catch(() => {});
    return () => { cancelled = true; window.removeEventListener('storage', syncFilters); };
  }, []);
  // Keep a saved selection visible even if its collector is temporarily unavailable.
  const options = [...new Set([...servers, ...(serverId ? [serverId] : [])])].sort();
  return (
    <div className="flex flex-wrap items-center gap-3 text-sm">
      <label className="flex items-center gap-2">Period
        <select aria-label="Detection period" value={hours} onChange={(event) => setHours(Number(event.target.value) as DetectionPeriod)} className="rounded border border-border bg-card p-2">
          <option value={1}>Last hour</option><option value={24}>Last 24 hours</option><option value={168}>Last 7 days</option>
        </select>
      </label>
      <label className="flex items-center gap-2">Server
        <select aria-label="Detection server" value={serverId} onChange={(event) => setServerId(event.target.value)} className="rounded border border-border bg-card p-2">
          <option value="">All servers</option>{options.map((server) => <option key={server}>{server}</option>)}
        </select>
      </label>
      <p className="text-muted-foreground">Shared by Dashboard and Threat Map. Views show up to 500 newest matches; charts and totals use the same selection.</p>
    </div>
  );
}
