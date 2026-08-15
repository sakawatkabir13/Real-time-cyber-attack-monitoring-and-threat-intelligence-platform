import { useMemo } from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';
import { Stats } from '@/hooks/useThreatFeed';

interface ThreatChartsProps {
  stats: Stats;
}

const ATTACK_COLORS: Record<string, string> = {
  ddos: 'hsl(0, 80%, 55%)',
  port_scan: 'hsl(40, 95%, 55%)',
  botnet: 'hsl(200, 80%, 40%)',
  brute_force: 'hsl(180, 80%, 45%)',
  malware: 'hsl(320, 70%, 50%)',
  phishing: 'hsl(280, 60%, 50%)',
};

export default function ThreatCharts({ stats }: ThreatChartsProps) {
  const timeData = useMemo(() => stats.threatsByHour, [stats]);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div className="bg-card/80 backdrop-blur-sm border border-border rounded-lg p-4">
        <h3 className="text-sm font-mono text-primary uppercase tracking-wider mb-4">Threat Timeline (24h)</h3>
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={timeData}>
            <defs>
              <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="hsl(160, 100%, 45%)" stopOpacity={0.3} />
                <stop offset="95%" stopColor="hsl(160, 100%, 45%)" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="hour" tick={{ fontSize: 10, fill: 'hsl(220, 10%, 55%)' }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fontSize: 10, fill: 'hsl(220, 10%, 55%)' }} axisLine={false} tickLine={false} />
            <Tooltip contentStyle={{ background: 'hsl(220, 18%, 10%)', border: '1px solid hsl(220, 15%, 18%)', borderRadius: '8px', fontSize: '12px', fontFamily: 'JetBrains Mono', color: 'hsl(160, 30%, 85%)' }} />
            <Area type="monotone" dataKey="count" stroke="hsl(160, 100%, 45%)" fill="url(#threatGrad)" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <div className="bg-card/80 backdrop-blur-sm border border-border rounded-lg p-4">
        <h3 className="text-sm font-mono text-primary uppercase tracking-wider mb-4">Attack Distribution</h3>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={stats.topAttackTypes} layout="vertical">
            <XAxis type="number" tick={{ fontSize: 10, fill: 'hsl(220, 10%, 55%)' }} axisLine={false} tickLine={false} />
            <YAxis type="category" dataKey="type" tick={{ fontSize: 10, fill: 'hsl(220, 10%, 55%)', fontFamily: 'JetBrains Mono' }} axisLine={false} tickLine={false} width={80} />
            <Tooltip contentStyle={{ background: 'hsl(220, 18%, 10%)', border: '1px solid hsl(220, 15%, 18%)', borderRadius: '8px', fontSize: '12px', fontFamily: 'JetBrains Mono', color: 'hsl(160, 30%, 85%)' }} />
            <Bar dataKey="count" radius={[0, 4, 4, 0]}>
              {stats.topAttackTypes.map((entry) => (
                <Cell key={entry.type} fill={ATTACK_COLORS[entry.type] || 'hsl(160, 100%, 45%)'} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
