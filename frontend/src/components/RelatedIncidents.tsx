import { useEffect, useState } from 'react';
import { useAppStore } from '@/store/appStore';

interface RelatedIncident {
  id: string; serverId: string; type: string; path: string | null;
  sourceCount: number; alertCount: number; explanation: string; lastSeen: string;
}

interface RelatedIncidentFilters {
  serverId?: string;
  attackType?: string;
  minimumSeverity?: string;
  verdict?: string;
  days?: number;
  search?: string;
}

export default function RelatedIncidents({ serverId, attackType, minimumSeverity, verdict, days, search }: RelatedIncidentFilters = {}) {
  const [groups, setGroups] = useState<RelatedIncident[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const autoRefresh = useAppStore((state) => state.settings.autoRefresh);
  useEffect(() => {
    const controller = new AbortController();
    let inFlight = false;
    setGroups([]);
    setError('');
    setLoading(true);
    const load = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const filters = new URLSearchParams({ limit: '50' });
        if (serverId) filters.set('server_id', serverId);
        if (attackType) filters.set('attack_type', attackType);
        if (minimumSeverity) filters.set('minimum_severity', minimumSeverity);
        if (verdict) filters.set('verdict', verdict);
        if (search) filters.set('search', search);
        if (days) filters.set('since', new Date(Date.now() - days * 86400000).toISOString());
        const response = await fetch(`/api/incidents?${filters}`, { signal: controller.signal });
        if (!response.ok) throw new Error();
        const values = await response.json() as RelatedIncident[];
        if (!controller.signal.aborted) { setGroups(values); setError(''); }
      } catch {
        if (!controller.signal.aborted) setError('Related incidents could not be loaded.');
      } finally { inFlight = false; if (!controller.signal.aborted) setLoading(false); }
    };
    void load();
    const timer = autoRefresh ? window.setInterval(() => void load(), 60000) : null;
    return () => { controller.abort(); if (timer !== null) window.clearInterval(timer); };
  }, [autoRefresh, serverId, attackType, minimumSeverity, verdict, days, search]);
  return (
    <section className="space-y-3" aria-label="Related incidents">
      <h2 className="text-sm font-mono">Possible related incidents</h2>
      <p className="text-xs text-muted-foreground">Grouped by similar evidence. This does not establish a common attacker.</p>
      {error && <p role="status" className="text-xs">{error}</p>}
      {!error && groups.length === 0 && <p role="status" className="text-xs text-muted-foreground">{loading ? 'Loading related groups…' : 'No related groups match these filters.'}</p>}
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
