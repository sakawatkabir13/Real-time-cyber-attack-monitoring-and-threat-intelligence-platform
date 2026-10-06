import { useDetectionViewFeed } from '@/hooks/useDetectionViewFeed';
import ThreatMap from '@/components/ThreatMap';
import CollectorControl from '@/components/CollectorControl';
import FeedStatus from '@/components/FeedStatus';
import DetectionFilters from '@/components/DetectionFilters';

export default function MapPage() {
  const { hours, serverId, events, liveEvent, subscribeToDetections, connection, updatedAt, error, refresh } = useDetectionViewFeed();

  return (
    <div className="p-6 space-y-4 h-full flex flex-col">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold font-display text-foreground">Global Threat Map</h1>
          <p className="text-sm font-mono text-muted-foreground">Live-updating HTTP detections · approximate source locations</p>
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
      <div className="flex-1 min-h-[460px]">
        <ThreatMap key={`${hours}:${serverId}`} events={events} liveEvent={liveEvent} subscribeToDetections={subscribeToDetections} />
      </div>
    </div>
  );
}
