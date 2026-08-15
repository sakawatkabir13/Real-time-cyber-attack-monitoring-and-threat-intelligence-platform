import { Activity, AlertTriangle, Shield, Wifi } from 'lucide-react';
import { useThreatFeed } from '@/hooks/useThreatFeed';
import StatCard from '@/components/StatCard';
import ThreatTable from '@/components/ThreatTable';
import ThreatCharts from '@/components/ThreatCharts';
import ThreatMap from '@/components/ThreatMap';
import AnomalyChart from '@/components/AnomalyChart';
import LiveEventFeed from '@/components/LiveEventFeed';
import AlertQueue from '@/components/AlertQueue';
import { useMemo } from 'react';
import CollectorControl from '@/components/CollectorControl';

export default function Dashboard() {
  const { events, stats, liveEvent } = useThreatFeed();

  const anomalyData = useMemo(() => {
    if (events.length === 0) return [];
    
    // Take the last 20 events with an anomaly score and map them for the chart
    return [...events]
      .filter(e => e.anomaly_score !== undefined && e.anomaly_score !== null)
      .slice(0, 20)
      .reverse()
      .map(e => ({
        time: new Date(e.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        score: Math.round(e.anomaly_score || 0),
      }));
  }, [events]);

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold font-display text-foreground">Threat Dashboard</h1>
          <p className="text-sm font-mono text-muted-foreground">Real-time cyber threat monitoring</p>
        </div>
        <CollectorControl />
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Attacks/sec"
          value={stats.attacksPerSecond}
          icon={<Activity className="h-5 w-5" />}
          trend={stats.attacksPerSecond > 5 ? `+${stats.attacksPerSecond}` : undefined}
          variant={stats.attacksPerSecond > 10 ? 'danger' : 'default'}
        />
        <StatCard
          title="Critical Alerts"
          value={stats.criticalAlerts}
          icon={<AlertTriangle className="h-5 w-5" />}
          variant={stats.criticalAlerts > 0 ? 'warning' : 'default'}
        />
        <StatCard
          title="Unique IPs"
          value={stats.uniqueIPs}
          icon={<Shield className="h-5 w-5" />}
        />
        <StatCard
          title="Total Events"
          value={stats.totalThreats.toLocaleString()}
          icon={<Wifi className="h-5 w-5" />}
          variant="success"
        />
      </div>

      {/* Map */}
      <div className="h-[500px]">
        <ThreatMap events={events} liveEvent={liveEvent} />
      </div>

      {/* Grid for Anomaly, Feed, Queue */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-1">
          <AlertQueue />
        </div>
        <div className="lg:col-span-1">
          <LiveEventFeed events={events} />
        </div>
        <div className="lg:col-span-1">
          <AnomalyChart data={anomalyData} />
        </div>
      </div>

      {/* Charts */}
      <ThreatCharts stats={stats} />

      {/* Table */}
      <ThreatTable events={events} maxRows={20} />
    </div>
  );
}
