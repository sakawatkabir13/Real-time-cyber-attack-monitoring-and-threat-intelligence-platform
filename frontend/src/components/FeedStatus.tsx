export default function FeedStatus({ connection, updatedAt, error, onRefresh }: {
  connection: string; updatedAt: string | null; error?: string; onRefresh: () => void;
}) {
  return <div className="flex flex-wrap items-center gap-3 rounded border border-border bg-card/70 px-3 py-2 text-sm">
    <span role="status" className={connection === 'live' ? 'text-success' : 'text-warning'}>
      {connection === 'live' ? 'Live connection' : connection === 'paused' ? 'Auto refresh off' : connection === 'connecting' ? 'Connecting live feed…' : 'Live feed disconnected · retrying'}
    </span>
    <span className="text-muted-foreground">{updatedAt ? `Snapshot updated ${new Date(updatedAt).toLocaleTimeString()}` : 'Waiting for snapshot'}</span>
    {error && <span role="alert" className="text-destructive">{error} · displayed data may be stale</span>}
    <button onClick={onRefresh} className="ml-auto rounded border border-border px-3 py-2 hover:bg-muted">Refresh now</button>
  </div>;
}
