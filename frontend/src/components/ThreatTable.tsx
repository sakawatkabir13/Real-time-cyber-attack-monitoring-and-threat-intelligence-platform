import { ThreatEvent } from '@/hooks/useThreatFeed';
import { cn } from '@/lib/utils';

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
  return (
    <div className="bg-card/80 backdrop-blur-sm border border-border rounded-lg overflow-hidden">
      <div className="p-4 border-b border-border">
        <h3 className="text-sm font-mono text-primary uppercase tracking-wider">Live Threat Feed</h3>
      </div>
      <div className="overflow-auto max-h-[500px]">
        <table className="w-full text-xs font-mono">
          <thead>
            <tr className="border-b border-border text-muted-foreground">
              <th className="text-left p-3">STATUS</th>
              <th className="text-left p-3">IP</th>
              <th className="text-left p-3">PORT</th>
              <th className="text-left p-3">TYPE</th>
              <th className="text-left p-3">COUNTRY</th>
              <th className="text-left p-3">TIME</th>
              <th className="text-left p-3">EXPLANATION</th>
            </tr>
          </thead>
          <tbody>
            {events.slice(0, maxRows).map((event, i) => (
              <tr
                key={event.id}
                className={cn(
                  'border-b border-border/50 transition-colors hover:bg-muted/30',
                  i === 0 && 'bg-primary/5'
                )}
              >
                <td className="p-3">
                  <div className="flex items-center gap-2">
                    <div className={cn('h-2 w-2 rounded-full', severityDot[event.severity] || severityDot.low)} />
                    <span className={severityColor[event.severity] || severityColor.low}>{event.severity.toUpperCase()}</span>
                  </div>
                </td>
                <td className={cn('p-3 font-medium text-foreground')}>{event.source_ip}</td>
                <td className="p-3 text-muted-foreground">{event.dest_port}</td>
                <td className="p-3 text-foreground">
                  <span className={cn(
                    'px-2 py-0.5 rounded text-[10px] uppercase',
                    event.attack_type === 'ddos' || event.attack_type === 'malware'
                      ? 'bg-destructive/20 text-destructive'
                      : event.attack_type === 'port_scan'
                      ? 'bg-warning/20 text-warning'
                      : 'bg-secondary/20 text-secondary'
                  )}>
                    {event.attack_type ? event.attack_type.replace('_', ' ') : 'UNKNOWN'}
                  </span>
                </td>
                <td className="p-3 text-muted-foreground">{event.country}</td>
                <td className="p-3 text-muted-foreground">
                  {new Date(event.timestamp).toLocaleTimeString()}
                </td>
                <td className="p-3 text-muted-foreground italic text-[10px] max-w-xs truncate" title={event.explanation}>
                  {event.explanation || "-"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
