import React from 'react';
import { AlertTriangle } from 'lucide-react';
import { useAppStore } from '../store/appStore';

export default function AlertQueue() {
  const alerts = useAppStore((state) => state.alerts);
  const sensitivity = useAppStore((state) => state.settings.alertSensitivity);
  const ranks = { low: 0, medium: 1, high: 2, critical: 3 };
  const visibleAlerts = alerts.filter((alert) =>
    !alert.acknowledged
    && ranks[alert.severity.toLowerCase() as keyof typeof ranks] >= ranks[sensitivity]);

  return (
    <div className="bg-card/80 backdrop-blur-sm border border-border rounded-lg p-4 h-[300px] flex flex-col">
      <div className="flex items-center gap-2 mb-4">
        <AlertTriangle className="w-4 h-4 text-warning" />
        <h3 className="text-sm font-mono text-warning uppercase tracking-wider">Alert Queue</h3>
      </div>
      <div className="flex-1 overflow-y-auto space-y-2 pr-2">
        {visibleAlerts.length === 0 ? (
          <div className="text-xs text-muted-foreground font-mono text-center mt-10">No recent alerts</div>
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
              <div className="text-slate-300 mb-1">{alert.type} - {alert.sourceIp} → {alert.targetIp}</div>
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
