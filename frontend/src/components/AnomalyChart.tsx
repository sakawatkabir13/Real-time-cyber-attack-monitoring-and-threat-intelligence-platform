import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import type { ThreatEvent } from '@/hooks/useThreatFeed';
import { useInvestigation } from '@/components/EventInspector';

interface AnomalyData {
  time: string;
  score: number;
  event?: ThreatEvent;
}

interface AnomalyChartProps {
  data: AnomalyData[];
}

export default function AnomalyChart({ data }: AnomalyChartProps) {
  const { inspectEvent } = useInvestigation();
  return (
    <div className="bg-card/80 backdrop-blur-sm border border-border rounded-lg p-4">
      <h3 className="text-sm font-mono text-primary uppercase tracking-wider">ML Anomaly Findings</h3>
      <p className="text-[11px] text-muted-foreground mb-3">Scored ML incidents only · rule scores excluded</p>
      {data.length === 0 ? (
        <div className="h-[200px] flex items-center justify-center text-center text-xs text-muted-foreground">
          No ML anomaly findings yet. Rule-based detection remains active.
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={data} onClick={(value) => { const event = value?.activePayload?.[0]?.payload?.event as ThreatEvent | undefined; if (event) inspectEvent(event); }}>
            <defs>
              <linearGradient id="anomalyGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="hsl(0, 80%, 55%)" stopOpacity={0.3} />
                <stop offset="95%" stopColor="hsl(0, 80%, 55%)" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="time" tick={{ fontSize: 10, fill: 'hsl(220, 10%, 55%)' }} axisLine={false} tickLine={false} />
            <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: 'hsl(220, 10%, 55%)' }} axisLine={false} tickLine={false} />
            <Tooltip contentStyle={{ background: 'hsl(220, 18%, 10%)', border: '1px solid hsl(220, 15%, 18%)', borderRadius: '8px', fontSize: '12px', fontFamily: 'JetBrains Mono', color: 'hsl(160, 30%, 85%)' }} />
            <Area type="monotone" dataKey="score" stroke="hsl(0, 80%, 55%)" fill="url(#anomalyGrad)" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      )}
      {data.length > 0 && <details className="text-sm"><summary className="cursor-pointer text-muted-foreground">Inspect scored findings</summary>{data.map((row, index) => row.event && <button key={row.event.id || index} onClick={() => inspectEvent(row.event!)} className="block min-h-10 w-full text-left hover:bg-muted">{row.time} · {row.score}/100</button>)}</details>}
    </div>
  );
}
