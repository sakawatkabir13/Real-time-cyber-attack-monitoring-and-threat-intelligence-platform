import { useEffect, useState } from 'react';
import { useAppStore } from '@/store/appStore';

interface RelatedIncident {
  id: string; serverId: string; type: string; path: string | null;
  sourceCount: number; alertCount: number; explanation: string; lastSeen: string;
}

export default function RelatedIncidents() {
  const [groups, setGroups] = useState<RelatedIncident[]>([]);
  const [error, setError] = useState('');
  const autoRefresh = useAppStore((state) => state.settings.autoRefresh);
  useEffect(() => {
    const controller = new AbortController();
    const load = async () => {
      try {
        const response = await fetch('/api/incidents?limit=50', { signal: controller.signal });
        if (!response.ok) throw new Error();
        setGroups(await response.json() as RelatedIncident[]);
        setError('');
      } catch {
        if (!controller.signal.aborted) setError('Related incidents could not be loaded.');
      }
    };
    void load();
    const timer = autoRefresh ? window.setInterval(() => void load(), 60000) : null;
    return () => { controller.abort(); if (timer !== null) window.clearInterval(timer); };
  }, [autoRefresh]);
  return (
    <section className="space-y-3" aria-label="Related incidents">
      <h2 className="text-sm font-mono">Possible related incidents</h2>
      <p className="text-xs text-muted-foreground">Grouped by similar evidence. This does not establish a common attacker.</p>
      {error && <p role="status" className="text-xs">{error}</p>}
      {!error && groups.length === 0 && <p className="text-xs text-muted-foreground">No related groups identified yet.</p>}
      {groups.map((group) => (
        <article key={group.id} id={`incident-${group.id}`} className="border border-border rounded-lg p-3 text-xs space-y-1">
          <p className="font-semibold">{group.serverId} · {group.type.replace(/_/g, ' ')} · {group.sourceCount} sources / {group.alertCount} alerts</p>
          <p className="font-mono break-all">{group.path}</p>
          <p className="text-muted-foreground">{group.explanation}</p>
          <p>Last seen: {new Date(group.lastSeen).toLocaleString()}</p>
        </article>
      ))}
    </section>
  );
}
