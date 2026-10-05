import { useAppStore } from '@/store/appStore';
import { cn } from '@/lib/utils';
import { Bell, Check, AlertTriangle, ShieldAlert, Bot, type LucideIcon } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import AlertReviewForm from '@/components/AlertReviewForm';
import RelatedIncidents from '@/components/RelatedIncidents';
import { useState } from 'react';
import { useInvestigation } from '@/components/EventInspector';
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog';

const alertIcons: Record<string, LucideIcon> = {
  port_scan: ShieldAlert,
  ddos: AlertTriangle,
  botnet: Bot,
};

const alertColors: Record<string, string> = {
  critical: 'border-destructive/40 bg-destructive/5',
  high: 'border-warning/40 bg-warning/5',
  medium: 'border-secondary/40 bg-secondary/5',
};

export default function AlertsPage() {
  const { alerts, acknowledgeAlert, resolveAlert, settings, alertsError, alertsUpdatedAt, loadAlerts } = useAppStore();
  const { inspectQuery } = useInvestigation();
  const [search, setSearch] = useState(new URLSearchParams(window.location.search).get('search') || '');
  const [severityFilter, setSeverityFilter] = useState(settings.alertSensitivity);
  const [serverFilter, setServerFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('');
  const [days, setDays] = useState('');
  const [pendingResolve, setPendingResolve] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState('');
  const acknowledge = async (id: string) => { setBusy(true); setActionError(''); if (!await acknowledgeAlert(id)) setActionError('Acknowledgement failed. Retry when the connection is available.'); setBusy(false); };
  const resolve = async () => { if (!pendingResolve) return; setBusy(true); setActionError(''); if (await resolveAlert(pendingResolve)) setPendingResolve(null); else setActionError('Resolution failed. The alert has not been confirmed resolved.'); setBusy(false); };
  const ranks = { low: 0, medium: 1, high: 2, critical: 3 };
  const visibleAlerts = alerts.filter((alert) =>
    ranks[alert.severity.toLowerCase() as keyof typeof ranks] >= ranks[severityFilter]
    && (!serverFilter || alert.serverId === serverFilter)
    && (!typeFilter || alert.type === typeFilter)
    && (!verdictFilter || alert.verdict === verdictFilter)
    && (!days || Date.parse(alert.lastSeen) >= Date.now() - Number(days) * 86400000)
    && `${alert.sourceIp} ${alert.serverId} ${alert.type} ${alert.explanation || ''}`.toLowerCase().includes(search.toLowerCase()));

  const unacked = visibleAlerts.filter(a => a.status === 'new');
  const acked = visibleAlerts.filter(a => a.status === 'acknowledged');
  const resolved = visibleAlerts.filter(a => a.status === 'resolved');

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold font-display text-foreground">Alerts</h1>
          <p className="text-sm font-mono text-muted-foreground">Detected threat patterns & anomalies</p>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-destructive/10 border border-destructive/20">
          <Bell className="h-4 w-4 text-destructive" />
          <span className="text-xs font-mono text-destructive">{unacked.length} ACTIVE</span>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-3 text-sm text-muted-foreground"><span>{alertsUpdatedAt ? `Alerts updated ${new Date(alertsUpdatedAt).toLocaleTimeString()}` : 'Loading alerts…'} · {settings.autoRefresh ? 'Polling every 30 seconds' : 'Auto refresh off'}</span><button onClick={() => void loadAlerts()} className="rounded border border-border px-3 py-2">Refresh alerts</button></div>
      {alertsError && <p role="alert" className="text-destructive">{alertsError} · displayed alerts may be stale</p>}
      <div className="grid gap-3 rounded border border-border bg-card p-4 sm:grid-cols-2 lg:grid-cols-3">
        <label className="text-sm">Search<input aria-label="Search alerts" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="IP, server or evidence" className="mt-1 w-full rounded border border-border bg-background p-2" /></label>
        <label className="text-sm">Minimum severity<select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value as typeof severityFilter)} className="mt-1 w-full rounded border border-border bg-background p-2">{Object.keys(ranks).map((rank) => <option key={rank}>{rank}</option>)}</select></label>
        <label className="text-sm">Server<select value={serverFilter} onChange={(event) => setServerFilter(event.target.value)} className="mt-1 w-full rounded border border-border bg-background p-2"><option value="">All servers</option>{[...new Set(alerts.map((alert) => alert.serverId))].map((server) => <option key={server}>{server}</option>)}</select></label>
        <label className="text-sm">Detection type<select value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)} className="mt-1 w-full rounded border border-border bg-background p-2"><option value="">All types</option>{[...new Set(alerts.map((alert) => alert.type))].map((type) => <option key={type} value={type}>{type.replace(/_/g, ' ')}</option>)}</select></label>
        <label className="text-sm">Review result<select value={verdictFilter} onChange={(event) => setVerdictFilter(event.target.value)} className="mt-1 w-full rounded border border-border bg-background p-2"><option value="">All results</option>{['unreviewed', 'confirmed_malicious', 'legitimate', 'misconfiguration', 'uncertain'].map((value) => <option key={value} value={value}>{value.replace(/_/g, ' ')}</option>)}</select></label>
        <label className="text-sm">Last seen<select value={days} onChange={(event) => setDays(event.target.value)} className="mt-1 w-full rounded border border-border bg-background p-2"><option value="">All loaded history</option><option value="1">Last 24 hours</option><option value="7">Last 7 days</option><option value="30">Last 30 days</option></select></label>
        <p className="text-xs text-muted-foreground sm:col-span-2 lg:col-span-3">Showing {visibleAlerts.length} of {alerts.length} loaded alerts (latest 500). {alerts.length - visibleAlerts.length} hidden by filters. Workflow status and investigation result are separate.</p>
      </div>
      {actionError && <p role="alert" className="text-destructive">{actionError}</p>}
      <Dialog open={pendingResolve !== null} onOpenChange={(open) => { if (!busy && !open) setPendingResolve(null); }}>
        <DialogContent><DialogTitle>Resolve this alert?</DialogTitle><DialogDescription>This closes the alert workflow. It does not mark traffic legitimate or malicious; record that separately in the investigation.</DialogDescription><div className="flex flex-wrap justify-end gap-3"><button disabled={busy} onClick={() => setPendingResolve(null)} className="rounded border border-border px-4 py-2">Cancel</button><button disabled={busy} onClick={() => void resolve()} className="rounded bg-primary px-4 py-2 text-primary-foreground">{busy ? 'Resolving…' : 'Confirm resolution'}</button></div></DialogContent>
      </Dialog>

      <RelatedIncidents />

      <AnimatePresence mode="popLayout">
        {unacked.length === 0 && (
          <div className="flex flex-col items-center py-16 text-muted-foreground">
            <Check className="h-12 w-12 mb-3 opacity-30" />
            <p className="font-mono text-sm">No active alerts</p>
            <p className="font-mono text-xs mt-1 text-muted-foreground">No new alerts match these filters. Check the collector status separately.</p>
          </div>
        )}

        {unacked.map(alert => {
          const Icon = alertIcons[alert.type] || AlertTriangle;
          const severity = alert.severity.toLowerCase();
          return (
            <motion.div
              key={alert.id}
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, x: 100 }}
              className={cn(
                'border rounded-lg p-4 flex flex-wrap items-start gap-4',
                alertColors[severity] || alertColors.medium
              )}
            >
              <div className={cn(
                'p-2 rounded-md',
                severity === 'critical' ? 'bg-destructive/20 text-destructive' :
                severity === 'high' ? 'bg-warning/20 text-warning' :
                'bg-secondary/20 text-secondary'
              )}>
                <Icon className="h-5 w-5" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className={cn(
                    'text-[10px] font-mono uppercase px-2 py-0.5 rounded',
                    severity === 'critical' ? 'bg-destructive/20 text-destructive' :
                    severity === 'high' ? 'bg-warning/20 text-warning' :
                    'bg-secondary/20 text-secondary'
                  )}>
                    {alert.severity}
                  </span>
                  <span className="text-[10px] font-mono text-muted-foreground uppercase">
                    {alert.type.replace(/_/g, ' ')}
                  </span>
                </div>
                <p className="text-sm font-mono text-foreground">{alert.explanation || "Threat detected"}</p>
                <p className="text-xs font-mono text-muted-foreground mt-1">
                  {new Date(alert.timestamp).toLocaleString()} • {alert.sourceIp}
                </p>
                <p className="text-xs text-muted-foreground">Server: {alert.serverId} · {alert.occurrenceCount} occurrences · New</p>
                <button className="min-h-10 text-sm text-primary underline" onClick={() => inspectQuery({ server_id: alert.serverId, source_ip: alert.sourceIp === 'Multiple sources' ? undefined : alert.sourceIp, attack_type: alert.type, since: alert.timestamp, until: new Date(Date.parse(alert.lastSeen) + 1000).toISOString() })}>View detection evidence</button>
                {alert.incidentGroupId && <a href={`#incident-${alert.incidentGroupId}`} className="text-xs underline">View possible related incident</a>}
                <AlertReviewForm alert={alert} />
              </div>
              <div className="shrink-0 flex flex-col gap-2">
                <button
                  disabled={busy}
                  onClick={() => void acknowledge(alert.id)}
                  className="px-3 py-1.5 text-xs font-mono rounded border border-border text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors"
                >
                  Acknowledge
                </button>
                <button
                  disabled={busy}
                  onClick={() => setPendingResolve(alert.id)}
                  className="px-3 py-1.5 text-xs font-mono rounded border border-success/40 text-success hover:bg-success/10 transition-colors"
                >
                  Resolve
                </button>
              </div>
            </motion.div>
          );
        })}
      </AnimatePresence>

      {acked.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-sm font-mono text-muted-foreground uppercase tracking-wider">
            Acknowledged ({acked.length})
          </h2>
          {acked.map(alert => (
            <div key={alert.id} className="border border-border/50 rounded-lg p-3 flex gap-3">
              <div className="flex-1">
                <p className="text-sm">{alert.sourceIp} · {alert.serverId} · {alert.type.replace(/_/g, ' ')} · {new Date(alert.lastSeen).toLocaleString()}</p>
                <button className="min-h-10 text-sm text-primary underline" onClick={() => inspectQuery({ server_id: alert.serverId, source_ip: alert.sourceIp === 'Multiple sources' ? undefined : alert.sourceIp, attack_type: alert.type, since: alert.timestamp, until: new Date(Date.parse(alert.lastSeen) + 1000).toISOString() })}>View detection evidence</button>
                <p className="text-xs font-mono text-muted-foreground">{alert.explanation || "Threat detected"}</p>
                <AlertReviewForm alert={alert} />
              </div>
              <button
                disabled={busy}
                onClick={() => setPendingResolve(alert.id)}
                className="self-start px-3 py-1.5 text-xs font-mono rounded border border-success/40 text-success hover:bg-success/10"
              >
                Resolve
              </button>
            </div>
          ))}
        </div>
      )}

      {resolved.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-sm font-mono text-muted-foreground uppercase tracking-wider">
            Resolved ({resolved.length})
          </h2>
          {resolved.map(alert => (
            <div key={alert.id} className="border border-success/20 bg-success/5 rounded-lg p-3">
              <p className="text-sm">{alert.sourceIp} · {alert.serverId} · {alert.type.replace(/_/g, ' ')} · {new Date(alert.lastSeen).toLocaleString()}</p>
              <button className="min-h-10 text-sm text-primary underline" onClick={() => inspectQuery({ server_id: alert.serverId, source_ip: alert.sourceIp === 'Multiple sources' ? undefined : alert.sourceIp, attack_type: alert.type, since: alert.timestamp, until: new Date(Date.parse(alert.lastSeen) + 1000).toISOString() })}>View detection evidence</button>
              <p className="text-xs font-mono text-muted-foreground">{alert.explanation || "Threat detected"}</p>
              <AlertReviewForm alert={alert} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
