import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';
import type { Stats } from '@/hooks/useThreatFeed';

interface ThreatChartsProps {
  stats: Stats;
}

const DETECTION_COLORS: Record<string, string> = {
  scanner: 'hsl(40, 95%, 55%)',
  sql_injection: 'hsl(0, 80%, 55%)',
  xss: 'hsl(15, 80%, 55%)',
  path_traversal: 'hsl(330, 75%, 55%)',
  http_flood: 'hsl(280, 65%, 55%)',
  brute_force: 'hsl(200, 80%, 50%)',
  server_traffic_anomaly: 'hsl(260, 75%, 60%)',
  source_behavior_anomaly: 'hsl(175, 75%, 50%)',
  other: 'hsl(220, 10%, 55%)',
};

const localHour = (value: string) =>
  new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const detectionName = (value: string) => value.replace(/_/g, ' ');

export default function ThreatCharts({ stats }: ThreatChartsProps) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div className="bg-card/80 backdrop-blur-sm border border-border rounded-lg p-4">
        <h3 className="text-sm font-mono text-primary uppercase tracking-wider">Detection Timeline (24h)</h3>
        <p className="text-[11px] text-muted-foreground mb-3">Rolling 24 hours · times shown in your timezone</p>
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={stats.threatsByHour}>
            <defs>
              <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="hsl(160, 100%, 45%)" stopOpacity={0.3} />
                <stop offset="95%" stopColor="hsl(160, 100%, 45%)" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="hour" tickFormatter={localHour} tick={{ fontSize: 10, fill: 'hsl(220, 10%, 55%)' }} axisLine={false} tickLine={false} />
            <YAxis allowDecimals={false} tick={{ fontSize: 10, fill: 'hsl(220, 10%, 55%)' }} axisLine={false} tickLine={false} />
            <Tooltip labelFormatter={(value) => new Date(String(value)).toLocaleString()} contentStyle={{ background: 'hsl(220, 18%, 10%)', border: '1px solid hsl(220, 15%, 18%)', borderRadius: '8px', fontSize: '12px', fontFamily: 'JetBrains Mono', color: 'hsl(160, 30%, 85%)' }} />
            <Area type="monotone" dataKey="count" stroke="hsl(160, 100%, 45%)" fill="url(#threatGrad)" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <div className="bg-card/80 backdrop-blur-sm border border-border rounded-lg p-4">
        <h3 className="text-sm font-mono text-primary uppercase tracking-wider">Detection Distribution (24h)</h3>
        <p className="text-[11px] text-muted-foreground mb-3">Stored detections · not confirmed attacks</p>
        {stats.topAttackTypes.length === 0 ? (
          <div className="h-[200px] flex items-center justify-center text-xs text-muted-foreground">No detections in the last 24 hours</div>
        ) : (
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={stats.topAttackTypes} layout="vertical">
              <XAxis type="number" allowDecimals={false} tick={{ fontSize: 10, fill: 'hsl(220, 10%, 55%)' }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="type" tickFormatter={detectionName} tick={{ fontSize: 10, fill: 'hsl(220, 10%, 55%)', fontFamily: 'JetBrains Mono' }} axisLine={false} tickLine={false} width={130} />
              <Tooltip labelFormatter={(value) => detectionName(String(value))} contentStyle={{ background: 'hsl(220, 18%, 10%)', border: '1px solid hsl(220, 15%, 18%)', borderRadius: '8px', fontSize: '12px', fontFamily: 'JetBrains Mono', color: 'hsl(160, 30%, 85%)' }} />
              <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                {stats.topAttackTypes.map((entry) => (
                  <Cell key={entry.type} fill={DETECTION_COLORS[entry.type] || 'hsl(160, 100%, 45%)'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
