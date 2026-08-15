import { Pause, Play } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';

interface Collector {
  serverId: string;
  desiredState: 'running' | 'paused';
  reportedState: 'running' | 'paused' | 'offline';
  commandVersion: number;
  spoolDepth: number;
  agentVersion?: string | null;
  lastError?: string | null;
  lastSeen: string;
}

export default function CollectorControl({ compact = false }: { compact?: boolean }) {
  const [collectors, setCollectors] = useState<Collector[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const refresh = useCallback(async () => {
    try {
      const response = await fetch('/api/collectors');
      if (!response.ok) throw new Error(`Collector status failed (${response.status})`);
      const data = await response.json() as Collector[];
      setCollectors(data);
      setSelectedId((current) => data.some((item) => item.serverId === current)
        ? current : data[0]?.serverId ?? '');
      setError('');
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Collector status unavailable');
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 10_000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const selected = useMemo(
    () => collectors.find((item) => item.serverId === selectedId),
    [collectors, selectedId],
  );

  const toggle = async () => {
    if (!selected) return;
    setBusy(true);
    setError('');
    const desiredState = selected.desiredState === 'running' ? 'paused' : 'running';
    try {
      const response = await fetch(
        `/api/collectors/${encodeURIComponent(selected.serverId)}/command`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ desired_state: desiredState }),
        },
      );
      if (!response.ok) throw new Error(`Collector command failed (${response.status})`);
      const updated = await response.json() as Collector;
      setCollectors((current) => current.map((item) =>
        item.serverId === updated.serverId ? updated : item));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Collector command failed');
    } finally {
      setBusy(false);
    }
  };

  const active = selected?.reportedState === 'running';
  const waiting = selected && selected.reportedState !== 'offline'
    && selected.desiredState !== selected.reportedState;
  const status = !selected ? 'NO AGENT'
    : selected.reportedState === 'offline' ? 'OFFLINE'
      : waiting ? `${selected.desiredState.toUpperCase()}…`
        : selected.reportedState === 'paused' ? `PAUSED · ${selected.spoolDepth} QUEUED`
          : `FORWARDING · ${selected.spoolDepth} QUEUED`;

  return (
    <div className="flex items-center gap-2">
      {collectors.length > 1 && !compact && (
        <select
          value={selectedId}
          onChange={(event) => setSelectedId(event.target.value)}
          aria-label="Collector server"
          className="rounded-md border border-border bg-background px-2 py-2 text-xs font-mono"
        >
          {collectors.map((collector) => (
            <option key={collector.serverId} value={collector.serverId}>{collector.serverId}</option>
          ))}
        </select>
      )}
      <button
        type="button"
        disabled={!selected || busy}
        onClick={() => void toggle()}
        title={error || selected?.lastError || undefined}
        className={`flex items-center gap-2 rounded-md border px-3 py-2 font-mono text-xs disabled:opacity-50 ${
          selected?.desiredState === 'running'
            ? 'border-destructive/30 bg-destructive/20 text-destructive'
            : 'border-primary/30 bg-primary/20 text-primary'
        }`}
      >
        {selected?.desiredState === 'running'
          ? <Pause className="h-3 w-3" /> : <Play className="h-3 w-3" />}
        {selected?.desiredState === 'running' ? 'PAUSE AGENT' : 'RESUME AGENT'}
      </button>
      <div className={`flex items-center gap-2 rounded-md border px-3 py-1.5 ${
        active ? 'border-primary/20 bg-primary/10' : 'border-border bg-muted'
      }`} title={error || selected?.lastError || undefined}>
        <div className={`h-2 w-2 rounded-full ${
          active ? 'animate-pulse bg-primary'
            : selected?.reportedState === 'offline' ? 'bg-destructive' : 'bg-muted-foreground'
        }`} />
        <span className={`font-mono text-xs ${active ? 'text-primary' : 'text-muted-foreground'}`}>
          {status}
        </span>
      </div>
    </div>
  );
}
