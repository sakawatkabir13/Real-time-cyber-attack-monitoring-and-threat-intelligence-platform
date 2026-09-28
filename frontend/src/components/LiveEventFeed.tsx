import React from 'react';
import { ThreatEvent } from '../hooks/useThreatFeed';
import { Activity } from 'lucide-react';

interface LiveEventFeedProps {
  events: ThreatEvent[];
}

export default function LiveEventFeed({ events }: LiveEventFeedProps) {
  return (
    <div className="bg-card/80 backdrop-blur-sm border border-border rounded-lg p-4 h-[300px] flex flex-col">
      <div className="flex items-center gap-2 mb-4">
        <Activity className="w-4 h-4 text-primary animate-pulse" />
        <h3 className="text-sm font-mono text-primary uppercase tracking-wider">Recent Detection Feed</h3>
      </div>
      <div className="flex-1 overflow-y-auto space-y-2 pr-2">
        {events.length === 0 && <p className="text-xs text-muted-foreground text-center mt-10">No stored events yet</p>}
        {events.slice(0, 50).map((event) => (
          <div key={event.id} className="text-xs font-mono py-1 border-b border-border/50 last:border-0 flex flex-col gap-1">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-slate-200 font-bold">{event.attack_type?.replace(/_/g, ' ').toUpperCase() || 'UNKNOWN'}</p>
                <p className="text-muted-foreground">{event.source_ip} · {event.server_id}</p>
                {event.path && <p className="text-muted-foreground break-all">{event.method || 'HTTP'} {event.path} · HTTP {event.status_code ?? '—'}</p>}
              </div>
              <div className="text-right">
                <span
                  className={`px-2 py-1 rounded text-[10px] font-mono border ${
                    event.severity === 'critical'
                      ? 'bg-destructive/10 text-destructive border-destructive/20'
                      : event.severity === 'high'
                      ? 'bg-orange-500/10 text-orange-500 border-orange-500/20'
                      : event.severity === 'medium'
                      ? 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20'
                      : 'bg-green-500/10 text-green-500 border-green-500/20'
                  }`}
                >
                  {event.severity.toUpperCase()}
                </span>
                {event.anomaly_score != null && (
                  <p className="text-[10px] text-primary mt-1">Score: {event.anomaly_score.toFixed(0)}/100</p>
                )}
              </div>
            </div>
            <p className="text-[10px] text-muted-foreground">{new Date(event.timestamp).toLocaleString()}</p>
            {event.explanation && (
              <div className="mt-1 text-[10px] bg-black/40 border border-primary/10 rounded p-1.5 text-slate-300 font-mono italic">
                {event.explanation}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
