import { Activity, AlertTriangle, Shield, Wifi } from 'lucide-react';
import { useDetectionViewFeed } from '@/hooks/useDetectionViewFeed';
import StatCard from '@/components/StatCard';
import ThreatTable from '@/components/ThreatTable';
import ThreatCharts from '@/components/ThreatCharts';
import ThreatMap from '@/components/ThreatMap';
import AnomalyChart from '@/components/AnomalyChart';
import LiveEventFeed from '@/components/LiveEventFeed';
import AlertQueue from '@/components/AlertQueue';
import { useMemo } from 'react';
import CollectorControl from '@/components/CollectorControl';
import FeedStatus from '@/components/FeedStatus';
import DetectionFilters from '@/components/DetectionFilters';

export default function Dashboard() {
  const { hours, serverId, events, mlEvents, stats, liveEvent, subscribeToDetections, connection, updatedAt, error, refresh } = useDetectionViewFeed();

  const anomalyData = useMemo(() => {
    return [...mlEvents]
      .filter((event) => event.anomaly_score !== undefined && event.anomaly_score !== null)
      .reverse()
      .map((event) => ({
        time: new Date(event.timestamp).toLocaleString(),
        score: Math.round(event.anomaly_score!),
        event,
      }));
  }, [mlEvents]);

  return (
    <div className="p-4 sm:p-6 space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold font-display text-foreground">Threat Dashboard</h1>
          <p className="text-sm font-mono text-muted-foreground">Real-time cyber threat monitoring</p>
        </div>
        <CollectorControl serverId={serverId} />
      </div>
      <DetectionFilters />
      <FeedStatus connection={connection} updatedAt={updatedAt} error={error} onRefresh={refresh} />

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Detections/sec"
          description="Average over the last minute"
          value={stats.attacksPerSecond}
          icon={<Activity className="h-5 w-5" />}
          variant={stats.attacksPerSecond > 10 ? 'danger' : 'default'}
        />
        <StatCard
          title="Critical Alerts"
          description={`New alerts seen in the last ${hours} hours`}
          value={stats.criticalAlerts}
          icon={<AlertTriangle className="h-5 w-5" />}
          variant={stats.criticalAlerts > 0 ? 'warning' : 'default'}
        />
        <StatCard
          title="Unique IPs"
          description={`Detected sources · last ${hours} hours`}
          value={stats.uniqueIPs}
          icon={<Shield className="h-5 w-5" />}
        />
        <StatCard
          title="Total Events"
          description={`Stored detections · last ${hours} hours`}
          value={stats.totalThreats.toLocaleString()}
          icon={<Wifi className="h-5 w-5" />}
          variant="success"
        />
      </div>

      {/* Map */}
      <div className="h-[500px]">
        <ThreatMap key={`${hours}:${serverId}`} events={events} liveEvent={liveEvent} subscribeToDetections={subscribeToDetections} />
      </div>

      {/* Grid for Anomaly, Feed, Queue */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-1">
          <AlertQueue hours={hours} serverId={serverId} />
        </div>
        <div className="lg:col-span-1">
          <LiveEventFeed events={events} />
        </div>
        <div className="lg:col-span-1">
          <AnomalyChart data={anomalyData} />
        </div>
      </div>

      {/* Charts */}
      <ThreatCharts stats={stats} serverId={serverId} />

      {/* Table */}
      <ThreatTable events={events} maxRows={20} />
    </div>
  );
}
