import { useThreatFeed } from '@/hooks/useThreatFeed';
import ThreatMap from '@/components/ThreatMap';
import CollectorControl from '@/components/CollectorControl';

export default function MapPage() {
  const { events, liveEvent } = useThreatFeed();

  return (
    <div className="p-6 space-y-4 h-full flex flex-col">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold font-display text-foreground">Global Threat Map</h1>
          <p className="text-sm font-mono text-muted-foreground">Animated real-time attack visualization</p>
        </div>
        <div className="flex items-center gap-3">
          <CollectorControl compact />
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-destructive/10 border border-destructive/20">
            <div className="h-2 w-2 rounded-full bg-destructive animate-pulse" />
            <span className="text-xs font-mono text-destructive">{events.length} EVENTS</span>
          </div>
        </div>
      </div>
      <div className="flex-1 min-h-0">
        <ThreatMap events={events} liveEvent={liveEvent} />
      </div>
    </div>
  );
}
