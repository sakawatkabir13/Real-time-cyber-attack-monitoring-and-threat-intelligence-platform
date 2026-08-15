import React from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

interface AnomalyData {
  time: string;
  score: number;
}

interface AnomalyChartProps {
  data: AnomalyData[];
}

export default function AnomalyChart({ data }: AnomalyChartProps) {
  return (
    <div className="bg-card/80 backdrop-blur-sm border border-border rounded-lg p-4">
      <h3 className="text-sm font-mono text-primary uppercase tracking-wider mb-4">Anomaly Score Timeline</h3>
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={data}>
          <defs>
            <linearGradient id="anomalyGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="hsl(0, 80%, 55%)" stopOpacity={0.3} />
              <stop offset="95%" stopColor="hsl(0, 80%, 55%)" stopOpacity={0} />
            </linearGradient>
          </defs>
          <XAxis dataKey="time" tick={{ fontSize: 10, fill: 'hsl(220, 10%, 55%)' }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fontSize: 10, fill: 'hsl(220, 10%, 55%)' }} axisLine={false} tickLine={false} />
          <Tooltip 
            contentStyle={{ background: 'hsl(220, 18%, 10%)', border: '1px solid hsl(220, 15%, 18%)', borderRadius: '8px', fontSize: '12px', fontFamily: 'JetBrains Mono', color: 'hsl(160, 30%, 85%)' }} 
          />
          <Area type="monotone" dataKey="score" stroke="hsl(0, 80%, 55%)" fill="url(#anomalyGrad)" strokeWidth={2} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
