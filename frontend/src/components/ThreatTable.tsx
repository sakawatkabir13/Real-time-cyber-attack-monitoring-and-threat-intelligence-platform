import type { ThreatEvent } from '@/hooks/useThreatFeed';
import { cn } from '@/lib/utils';
import { useInvestigation } from '@/components/EventInspector';

const severityDot: Record<string, string> = {
  low: 'bg-muted-foreground',
  medium: 'bg-warning',
  high: 'bg-destructive',
  critical: 'bg-destructive animate-pulse',
};

const severityColor: Record<string, string> = {
  low: 'text-muted-foreground',
  medium: 'text-warning',
  high: 'text-destructive',
  critical: 'text-destructive font-bold',
};

interface ThreatTableProps {
  events: ThreatEvent[];
  maxRows?: number;
}

export default function ThreatTable({ events, maxRows = 15 }: ThreatTableProps) {
  const { inspectEvent } = useInvestigation();
  return (
    <div className="bg-card/80 backdrop-blur-sm border border-border rounded-lg overflow-hidden">
      <div className="p-4 border-b border-border">
        <h3 className="text-sm font-mono text-primary uppercase tracking-wider">Recent Detection Events</h3>
      </div>
      <div className="overflow-auto max-h-[500px]">
        <table className="w-full text-xs font-mono">
          <thead>
            <tr className="border-b border-border text-muted-foreground">
              <th className="text-left p-3">SEVERITY</th>
              <th className="text-left p-3">SOURCE IP</th>
              <th className="text-left p-3">REQUEST</th>
              <th className="text-left p-3">HTTP</th>
              <th className="text-left p-3">TYPE</th>
              <th className="text-left p-3">SERVER</th>
              <th className="text-left p-3">COUNTRY</th>
              <th className="text-left p-3">TIME</th>
              <th className="text-left p-3">EXPLANATION</th>
            </tr>
          </thead>
          <tbody>
            {events.length === 0 && (
              <tr><td colSpan={9} className="p-6 text-center text-muted-foreground">No stored events yet</td></tr>
            )}
            {events.slice(0, maxRows).map((event, index) => (
              <tr key={event.id} className={cn(
                'border-b border-border/50 transition-colors hover:bg-muted/30',
                index === 0 && 'bg-primary/5'
              )}>
                <td className="p-3">
                  <div className="flex items-center gap-2">
                    <div className={cn('h-2 w-2 rounded-full', severityDot[event.severity] || severityDot.low)} />
                    <span className={severityColor[event.severity] || severityColor.low}>{event.severity.toUpperCase()}</span>
                  </div>
                </td>
                <td className="p-3 font-medium text-foreground"><button onClick={() => inspectEvent(event)} className="min-h-9 text-left text-primary underline" aria-label={`Inspect event ${event.id} from ${event.source_ip}`}>{event.source_ip}</button></td>
                <td className="p-3 text-muted-foreground max-w-xs truncate" title={event.path ?? undefined}>
                  {event.path ? `${event.method || 'HTTP'} ${event.path}` : '—'}
                </td>
                <td className="p-3 text-muted-foreground">{event.status_code ?? '—'}</td>
                <td className="p-3 text-foreground">
                  <span className={cn('px-2 py-0.5 rounded text-[10px] uppercase',
                    event.severity === 'critical' || event.severity === 'high'
                      ? 'bg-destructive/20 text-destructive'
                      : event.severity === 'medium'
                        ? 'bg-warning/20 text-warning'
                        : 'bg-secondary/20 text-secondary'
                  )}>
                    {event.attack_type ? event.attack_type.replace(/_/g, ' ') : 'UNKNOWN'}
                  </span>
                </td>
                <td className="p-3 text-muted-foreground">{event.server_id}</td>
                <td className="p-3 text-muted-foreground">{event.country}</td>
                <td className="p-3 text-muted-foreground">{new Date(event.timestamp).toLocaleString()}</td>
                <td className="p-3 text-muted-foreground italic text-[10px] max-w-xs truncate" title={event.explanation ?? undefined}>
                  {event.explanation || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
