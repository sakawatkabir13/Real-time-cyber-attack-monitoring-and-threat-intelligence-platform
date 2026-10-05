import React from 'react';
import { AlertTriangle } from 'lucide-react';
import { useAppStore } from '../store/appStore';
import { useInvestigation } from '@/components/EventInspector';

export default function AlertQueue({ hours, serverId = '' }: { hours?: number; serverId?: string }) {
  const { inspectQuery } = useInvestigation();
  const alerts = useAppStore((state) => state.alerts);
  const sensitivity = useAppStore((state) => state.settings.alertSensitivity);
  const loading = useAppStore((state) => state.alertsLoading);
  const error = useAppStore((state) => state.alertsError);
  const ranks = { low: 0, medium: 1, high: 2, critical: 3 };
  const visibleAlerts = alerts.filter((alert) =>
    !alert.acknowledged
    && alert.status === 'new'
    && (!serverId || alert.serverId === serverId)
    && (!hours || Date.parse(alert.lastSeen) >= Date.now() - hours * 3600000)
    && ranks[alert.severity.toLowerCase() as keyof typeof ranks] >= ranks[sensitivity]);

  return (
    <div className="bg-card/80 backdrop-blur-sm border border-border rounded-lg p-4 h-[300px] flex flex-col">
      <div className="flex items-center gap-2 mb-4">
        <AlertTriangle className="w-4 h-4 text-warning" />
        <h3 className="text-sm font-mono text-warning uppercase tracking-wider">Alert Queue</h3>
      </div>
      <div className="flex-1 overflow-y-auto space-y-2 pr-2">
        {error && <p role="alert" className="text-sm text-destructive">{error} · alert data may be stale</p>}
        {visibleAlerts.length === 0 ? (
          <div className="text-xs text-muted-foreground font-mono text-center mt-10">
            {loading ? 'Loading alerts…' : alerts.some((alert) => !alert.acknowledged)
              ? 'No new alerts at this sensitivity'
              : 'No new alerts'}
          </div>
        ) : (
          visibleAlerts.map((alert) => (
            <div key={alert.id} className="text-xs font-mono py-2 px-2 bg-background/50 border border-border/50 rounded-md">
              <div className="flex justify-between items-center mb-1">
                <span className={
                  alert.severity === 'Critical' ? 'text-destructive font-bold' :
                  alert.severity === 'High' ? 'text-warning font-bold' :
                  alert.severity === 'Medium' ? 'text-secondary font-bold' : 'text-success font-bold'
                }>{alert.severity}</span>
                <span className="text-muted-foreground">{new Date(alert.timestamp).toLocaleTimeString()}</span>
              </div>
              <button className="mb-1 min-h-9 text-left text-foreground hover:underline" onClick={() => inspectQuery({ server_id: alert.serverId, source_ip: alert.sourceIp === 'Multiple sources' ? undefined : alert.sourceIp, attack_type: alert.type, since: alert.timestamp, until: new Date(Date.parse(alert.lastSeen) + 1000).toISOString() })}>{alert.type.replace(/_/g, ' ')} · {alert.sourceIp} · Server: {alert.serverId}</button>
              {alert.explanation && (
                <div className="text-[10px] text-muted-foreground italic border-t border-border/50 pt-1 mt-1">
                  {alert.explanation}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
