import { createContext, useContext, useRef, useState, type ReactNode } from 'react';
import type { ThreatEvent } from '@/hooks/useThreatFeed';
import { useAppStore } from '@/store/appStore';
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog';

type EventQuery = { server_id?: string; source_ip?: string; attack_type?: string; since?: string; until?: string };
const InvestigationContext = createContext({ inspectEvent: (_event: ThreatEvent) => {}, inspectQuery: (_query: EventQuery) => {} });
export const useInvestigation = () => useContext(InvestigationContext);

export default function EventInspector({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const [event, setEvent] = useState<ThreatEvent | null>(null);
  const [matches, setMatches] = useState<ThreatEvent[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const requestVersion = useRef(0);
  const alerts = useAppStore((state) => state.alerts);
  const inspectEvent = (value: ThreatEvent) => {
    requestVersion.current += 1;
    setEvent(value); setMatches([]); setError(''); setLoading(false); setOpen(true);
  };
  const inspectQuery = async (query: EventQuery) => {
    const version = ++requestVersion.current;
    setOpen(true); setEvent(null); setMatches([]); setError(''); setLoading(true);
    try {
      const params = new URLSearchParams({ limit: '50', ...query });
      const response = await fetch(`/api/events?${params}`);
      if (!response.ok) throw new Error(`Could not load related events (${response.status})`);
      const values = await response.json() as ThreatEvent[];
      if (version !== requestVersion.current) return;
      setMatches(values);
      if (values.length === 1) setEvent(values[0]);
    } catch (reason) {
      if (version === requestVersion.current) setError(reason instanceof Error ? reason.message : 'Events unavailable');
    } finally { if (version === requestVersion.current) setLoading(false); }
  };
  const related = event ? alerts.filter((alert) => alert.serverId === event.server_id && alert.sourceIp === event.source_ip && alert.type === event.attack_type) : [];
  return <InvestigationContext.Provider value={{ inspectEvent, inspectQuery: (query) => { void inspectQuery(query); } }}>
    {children}
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="max-h-[90dvh] w-[calc(100%-2rem)] max-w-2xl overflow-y-auto">
        <DialogTitle>{event ? 'Detection investigation' : 'Matching detection events'}</DialogTitle>
        <DialogDescription>{event ? 'Observed request and detector evidence. A detection requires investigation before confirmation.' : 'Up to 50 newest events matching your selection. Select one to inspect its evidence.'}</DialogDescription>
        {loading && <p role="status">Loading events…</p>}
        {error && <p role="alert" className="text-destructive">{error}</p>}
        {!loading && !error && !event && matches.length === 0 && <p>No stored events match this selection.</p>}
        {matches.length > 1 && <div className="max-h-48 space-y-2 overflow-y-auto">
          {matches.map((item) => <button key={item.id} onClick={() => setEvent(item)} className="w-full rounded border border-border p-3 text-left text-sm hover:bg-muted" aria-pressed={event?.id === item.id}>
            {item.attack_type.replace(/_/g, ' ')} · {item.source_ip} · {new Date(item.timestamp).toLocaleString()}
            <span className="block break-all text-muted-foreground">{item.method} {item.path || 'Aggregated traffic finding'}</span>
          </button>)}
        </div>}
        {event && <>
          <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-3 text-sm">
            <dt>Detection</dt><dd className="break-words">{event.attack_type.replace(/_/g, ' ')} · {event.severity}</dd>
            <dt>Source</dt><dd className="break-all">{event.source_ip} · {event.country}</dd>
            <dt>Site / server</dt><dd className="break-all">{event.host || event.server_id} ({event.server_id})</dd>
            <dt>Time</dt><dd>{new Date(event.timestamp).toLocaleString()}</dd>
            <dt>Request</dt><dd className="break-all">{event.path ? `${event.method || 'HTTP'} ${event.path}` : 'Aggregated traffic finding; no individual request'}</dd>
            <dt>HTTP status</dt><dd>{event.status_code ?? 'Not recorded'}</dd>
            <dt>ML score</dt><dd>{event.attack_type.endsWith('_anomaly') && event.anomaly_score != null ? `${event.anomaly_score.toFixed(0)} / 100` : 'Not an ML finding'}</dd>
          </dl>
          <section className="rounded border border-border bg-muted/30 p-4">
            <h3 className="mb-2 font-semibold">Detection evidence</h3>
            <p className="whitespace-pre-wrap break-words text-sm">{event.explanation || 'No additional explanation was recorded.'}</p>
          </section>
          <div className="flex flex-wrap gap-3 text-sm">
            {event.source_ip !== 'Multiple sources' && <a className="text-primary underline" href={`/ip-lookup?ip=${encodeURIComponent(event.source_ip)}`}>Look up source IP</a>}
            <a className="text-primary underline" href={`/alerts?search=${encodeURIComponent(event.source_ip)}`}>Review related alerts ({related.length} loaded)</a>
          </div>
          {related.length > 0 && <p className="text-xs text-muted-foreground">Related alerts share this source, server and detection type; they may cover a different time period.</p>}
        </>}
      </DialogContent>
    </Dialog>
  </InvestigationContext.Provider>;
}
