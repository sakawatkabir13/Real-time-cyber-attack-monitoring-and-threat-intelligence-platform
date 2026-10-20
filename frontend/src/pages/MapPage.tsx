import { useDetectionViewFeed } from '@/hooks/useDetectionViewFeed';
import ThreatMap from '@/components/ThreatMap';
import CollectorControl from '@/components/CollectorControl';
import FeedStatus from '@/components/FeedStatus';
import DetectionFilters from '@/components/DetectionFilters';

export default function MapPage() {
  const { hours, serverId, events, mapTarget, mapTargetLoading, trafficEvents, liveTrafficEvent, subscribeToTraffic, connection, updatedAt, error, refresh } = useDetectionViewFeed();

  return (
    <div className="p-6 space-y-4 h-full flex flex-col">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold font-display text-foreground">Global Threat Map</h1>
          <p className="text-sm font-mono text-muted-foreground">All observed HTTP requests · persistent markers for detections only</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <CollectorControl compact serverId={serverId} />
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-destructive/10 border border-destructive/20">
            <div className="h-2 w-2 rounded-full bg-primary" />
            <span className="text-xs font-mono text-destructive">{events.length} RECENT EVENTS</span>
          </div>
        </div>
      </div>
      <DetectionFilters />
      <FeedStatus connection={connection} updatedAt={updatedAt} error={error} onRefresh={refresh} />
      <div className="w-full flex-none">
        <ThreatMap key={`${hours}:${serverId}`} events={events} trafficEvents={trafficEvents ?? []} liveEvent={liveTrafficEvent} subscribeToTraffic={subscribeToTraffic} mapTarget={mapTarget} mapTargetLoading={mapTargetLoading} showRecentDetections />
      </div>
    </div>
  );
}
