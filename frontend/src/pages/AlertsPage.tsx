import { useAppStore } from '@/store/appStore';
import { cn } from '@/lib/utils';
import { Bell, Check, AlertTriangle, ShieldAlert, Bot, type LucideIcon } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

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
  const { alerts, acknowledgeAlert, settings } = useAppStore();
  const ranks = { low: 0, medium: 1, high: 2, critical: 3 };
  const visibleAlerts = alerts.filter((alert) =>
    ranks[alert.severity.toLowerCase() as keyof typeof ranks] >= ranks[settings.alertSensitivity]);

  const unacked = visibleAlerts.filter(a => !a.acknowledged);
  const acked = visibleAlerts.filter(a => a.acknowledged);

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold font-display text-foreground">Alerts</h1>
          <p className="text-sm font-mono text-muted-foreground">Detected threat patterns & anomalies</p>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-destructive/10 border border-destructive/20">
          <Bell className="h-4 w-4 text-destructive" />
          <span className="text-xs font-mono text-destructive">{unacked.length} ACTIVE</span>
        </div>
      </div>

      <AnimatePresence mode="popLayout">
        {unacked.length === 0 && (
          <div className="flex flex-col items-center py-16 text-muted-foreground">
            <Check className="h-12 w-12 mb-3 opacity-30" />
            <p className="font-mono text-sm">No active alerts</p>
            <p className="font-mono text-xs mt-1 text-muted-foreground/60">Start the collector to generate threat data</p>
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
                'border rounded-lg p-4 flex items-start gap-4',
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
                    {alert.type.replace('_', ' ')}
                  </span>
                </div>
                <p className="text-sm font-mono text-foreground">{alert.explanation || "Threat detected"}</p>
                <p className="text-xs font-mono text-muted-foreground mt-1">
                  {new Date(alert.timestamp).toLocaleString()} • {alert.sourceIp}
                </p>
              </div>
              <button
                onClick={() => acknowledgeAlert(alert.id)}
                className="shrink-0 px-3 py-1.5 text-xs font-mono rounded border border-border text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors"
              >
                ACK
              </button>
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
            <div key={alert.id} className="border border-border/50 rounded-lg p-3 opacity-50">
              <p className="text-xs font-mono text-muted-foreground">{alert.explanation || "Threat detected"}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
