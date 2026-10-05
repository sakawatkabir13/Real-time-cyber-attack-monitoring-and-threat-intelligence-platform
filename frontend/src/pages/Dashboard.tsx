import { Activity, AlertTriangle, Shield, Wifi } from 'lucide-react';
import { useThreatFeed } from '@/hooks/useThreatFeed';
import StatCard from '@/components/StatCard';
import ThreatTable from '@/components/ThreatTable';
import ThreatCharts from '@/components/ThreatCharts';
import ThreatMap from '@/components/ThreatMap';
import AnomalyChart from '@/components/AnomalyChart';
import LiveEventFeed from '@/components/LiveEventFeed';
import AlertQueue from '@/components/AlertQueue';
import { useEffect, useMemo, useState } from 'react';
import CollectorControl from '@/components/CollectorControl';
import FeedStatus from '@/components/FeedStatus';

export default function Dashboard() {
  const [hours, setHours] = useState(24);
  const [serverId, setServerId] = useState('');
  const [servers, setServers] = useState<string[]>([]);
  const { events, mlEvents, stats, liveEvent, connection, updatedAt, error, refresh } = useThreatFeed({ hours, serverId });
  useEffect(() => { let cancelled = false; fetch('/api/collectors').then((response) => response.ok ? response.json() : []).then((rows: Array<{ serverId: string }>) => { if (!cancelled) setServers(rows.map((row) => row.serverId)); }).catch(() => {}); return () => { cancelled = true; }; }, []);

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
      <div className="flex flex-wrap items-center gap-3 text-sm">
        <label className="flex items-center gap-2">Period <select aria-label="Dashboard period" value={hours} onChange={(event) => setHours(Number(event.target.value))} className="rounded border border-border bg-card p-2"><option value={1}>Last hour</option><option value={24}>Last 24 hours</option><option value={168}>Last 7 days</option></select></label>
        <label className="flex items-center gap-2">Server <select aria-label="Dashboard server" value={serverId} onChange={(event) => setServerId(event.target.value)} className="rounded border border-border bg-card p-2"><option value="">All servers</option>{servers.map((server) => <option key={server}>{server}</option>)}</select></label>
        <p className="text-muted-foreground">Charts and totals use this selection. Event views show up to 500 newest matches.</p>
      </div>
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
        <ThreatMap events={events} liveEvent={liveEvent} />
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
