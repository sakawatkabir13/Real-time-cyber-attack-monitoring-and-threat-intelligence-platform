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
  const { events, mlEvents, stats, liveEvent } = useThreatFeed();

  const anomalyData = useMemo(() => {
    return [...mlEvents]
      .filter((event) => event.anomaly_score !== undefined && event.anomaly_score !== null)
      .reverse()
      .map((event) => ({
        time: new Date(event.timestamp).toLocaleString(),
        score: Math.round(event.anomaly_score!),
      }));
  }, [mlEvents]);

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
          title="Detections/sec"
          value={stats.attacksPerSecond}
          icon={<Activity className="h-5 w-5" />}
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
