import { useMemo, useState } from 'react';
import type { KeyboardEvent } from 'react';
import { Info, MapPin, Radio, X } from 'lucide-react';
import { useInvestigation } from '@/components/EventInspector';
import { useReducedMotion } from 'framer-motion';
import { ComposableMap, Geographies, Geography, Marker, ZoomableGroup } from 'react-simple-maps';
import countries from 'world-atlas/countries-110m.json';

import type { MapTarget, SubscribeToDetections, ThreatEvent } from '@/hooks/useThreatFeed';
import LiveTrafficLayer from './LiveTrafficLayer';
import { point, severityColors, sourcePoint, targetPoint } from './mapGeometry';
import type { GeoPoint } from './mapGeometry';
import './ThreatMap.css';

interface ThreatMapProps {
  events: ThreatEvent[];
  /** Short-lived HTTP telemetry; never used for detection markers or counters. */
  trafficEvents?: ThreatEvent[];
  liveEvent: ThreatEvent | null;
  subscribeToTraffic?: SubscribeToDetections;
  mapTarget?: MapTarget | null;
  mapTargetLoading?: boolean;
  /** Show the separate recent-detections panel (used on the dedicated map page). */
  showRecentDetections?: boolean;
}

interface SelectedEvent {
  event: ThreatEvent;
  pinned: boolean;
}

function isAggregateEvent(event: ThreatEvent): boolean {
  return event.source_ip === 'Multiple sources' || event.attack_type === 'server_traffic_anomaly';
}

function detectionName(value: string): string {
  return value.replace(/_/g, ' ');
}

function eventTime(value: string): string {
  return new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export default function ThreatMap({
  events,
  trafficEvents = [],
  liveEvent,
  subscribeToTraffic,
  mapTarget = null,
  mapTargetLoading = false,
  showRecentDetections = true,
}: ThreatMapProps) {
  const { inspectEvent } = useInvestigation();
  const [activeCount, setActiveCount] = useState(0);
  const [selected, setSelected] = useState<SelectedEvent | null>(null);
  const reducedMotion = useReducedMotion();
  const configuredTarget = useMemo(
    () => point(mapTarget?.lng, mapTarget?.lat),
    [mapTarget?.lat, mapTarget?.lng],
  );

  const recentDetections = useMemo(() => {
    const bySource = new Map<string, { event: ThreatEvent; count: number }>();
    // Feed snapshots are newest first; retain the latest request for each IP.
    for (const event of events) {
      const key = event.source_ip === 'Multiple sources' ? event.server_id + ':aggregate' : event.source_ip;
      const existing = bySource.get(key);
      if (existing) existing.count += 1;
      else bySource.set(key, { event, count: 1 });
    }
    return [...bySource.values()];
  }, [events]);

  const historicalEvents = useMemo(() => {
    const markers = new Map<string, { event: ThreatEvent; count: number }>();
    for (const event of events) {
      const location = sourcePoint(event);
      if (!location) continue;
      const key = location[0].toFixed(1) + ':' + location[1].toFixed(1);
      const existing = markers.get(key);
      if (existing) existing.count += 1;
      else markers.set(key, { event, count: 1 });
    }
    return [...markers.values()];
  }, [events]);

  const aggregateEvents = useMemo(
    () => events.filter(isAggregateEvent).slice(0, 4),
    [events],
  );

  const targets = useMemo(() => {
    const byServer = new Map<string, { serverId: string; coordinates: GeoPoint }>();
    for (const event of [liveEvent, ...events]) {
      if (!event || byServer.has(event.server_id)) continue;
      const coordinates = targetPoint(event);
      if (coordinates) byServer.set(event.server_id, { serverId: event.server_id, coordinates });
      if (byServer.size >= 4) break;
    }
    // Use the standalone config marker only before an event supplies a
    // destination. This avoids rendering a duplicate marker when the event
    // snapshot already contains the monitored server.
    if (configuredTarget && mapTarget && byServer.size === 0) {
      byServer.set(mapTarget.serverId, { serverId: mapTarget.serverId, coordinates: configuredTarget });
    }
    return [...byServer.values()];
  }, [configuredTarget, events, liveEvent, mapTarget]);

  const showDetails = (event: ThreatEvent, pinned: boolean) => setSelected({ event, pinned });
  const hideUnpinned = () => setSelected((current) => current?.pinned ? current : null);
  const onMarkerKeyDown = (keyEvent: KeyboardEvent<SVGCircleElement>, event: ThreatEvent) => {
    if (keyEvent.key === 'Enter' || keyEvent.key === ' ') {
      keyEvent.preventDefault();
      showDetails(event, true);
    }
  };

  return (
    <div className={`${showRecentDetections ? 'flex min-h-[560px] flex-col gap-3' : 'flex h-full min-h-[400px] flex-col gap-3'}`}>
      <div
        style={showRecentDetections ? { height: 'min(78vh, 720px)' } : undefined}
        className={`vanguard-map relative flex flex-col overflow-hidden rounded-xl border border-[#1d3840] bg-[#061016] shadow-[inset_0_0_60px_rgba(0,180,190,0.035)] ${showRecentDetections ? 'min-h-[560px] flex-none' : 'min-h-0 flex-1'}`}>
        <div className="relative z-10 flex flex-wrap items-center justify-between gap-2 border-b border-[#1a323a] bg-[#071218]/95 px-4 py-3">
        <div className="flex items-center gap-3">
          <Radio className="h-4 w-4 text-cyan-300" aria-hidden="true" />
          <div>
            <h2 className="text-xs font-bold tracking-[0.18em] text-slate-100">LIVE HTTP TRAFFIC MAP</h2>
            <p className="text-[10px] text-slate-400">All requests · detection-only source dots · illustrative routes</p>
          </div>
          <span className="rounded-full border border-emerald-400/25 bg-emerald-400/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-300">
            LIVE · NO PLAYBACK QUEUE
          </span>
        </div>
        <div className="flex items-center gap-3">
          <div className="hidden items-center gap-2 text-[10px] text-slate-300 sm:flex" aria-label="Request behavior legend">
            {(['normal', 'low', 'medium', 'high', 'critical'] as const).map((severity) => (
              <span key={severity} className="flex items-center gap-1 capitalize">
                <span className="h-2 w-2 rounded-full" style={{ backgroundColor: severityColors[severity] }} />
                {severity}
              </span>
            ))}
          </div>
        </div>
        </div>

        <div className="vanguard-map-surface relative min-h-[230px] flex-1">
        <div className="pointer-events-none absolute left-3 top-3 z-10 rounded border border-cyan-300/20 bg-[#071218]/90 px-2 py-1 text-[10px] text-cyan-100">
          {reducedMotion ? 'System reduced-motion preference enabled' : `${activeCount} live arcs · immediate display`}
          <span className="block text-slate-400">Updates on receipt of access logs · not packet-level timing</span>
          {trafficEvents.some((event) => !sourcePoint(event) || !targetPoint(event, configuredTarget)) &&
            <span className="block text-slate-400">Some requests cannot be geolocated; no coordinates are invented.</span>}
        </div>
          <ComposableMap width={1400} height={620} projection="geoEqualEarth"
          projectionConfig={{ scale: 190 }} className="h-full w-full">
          <ZoomableGroup center={[0, 0]} zoom={1} minZoom={1} maxZoom={4}>
            <Geographies geography={countries}>
              {({ geographies }) => geographies.map((geography) => (
                <Geography key={geography.rsmKey} geography={geography}
                  fill="#0a1b22" stroke="#20505b" strokeWidth={0.55}
                  style={{
                    default: { outline: 'none' },
                    hover: { fill: '#12313a', outline: 'none' },
                    pressed: { outline: 'none' },
                  }}
                />
              ))}
            </Geographies>

            {historicalEvents.map(({ event, count }) => {
              const location = sourcePoint(event);
              if (!location) return null;
              return (
                <Marker key={'history-' + event.id} coordinates={location}>
                  <circle r={6} fill="transparent" stroke="transparent"
                    role="button" tabIndex={0}
                    aria-label={'Inspect ' + detectionName(event.attack_type) + ' from ' + event.source_ip}
                    onMouseEnter={() => showDetails(event, false)}
                    onMouseLeave={hideUnpinned}
                    onFocus={() => showDetails(event, false)}
                    onBlur={hideUnpinned}
                    onClick={() => showDetails(event, true)}
                    onKeyDown={(keyEvent) => onMarkerKeyDown(keyEvent, event)}
                    className="cursor-pointer focus-visible:outline-none"
                  />
                  <circle r={1.8} fill={severityColors[event.severity] || severityColors.low}
                    opacity={0.65} pointerEvents="none" />
                  {count > 1 && <text x={5} y={-5} fill="#d9fffd" fontSize={9} pointerEvents="none">×{count}</text>}
                </Marker>
              );
            })}

            <LiveTrafficLayer liveEvent={liveEvent} subscribeToTraffic={subscribeToTraffic}
              configuredTarget={configuredTarget} reducedMotion={Boolean(reducedMotion)}
              onActiveCount={setActiveCount} />

            {targets.map((target) => (
              <Marker key={target.serverId} coordinates={target.coordinates}>
                <circle r={12} fill="none" stroke="#5de5e7" strokeWidth={0.8} opacity={0.25} />
                <circle r={6} fill="#064b54" stroke="#a2f7f4" strokeWidth={1.3} />
                <circle r={2.2} fill="#d9fffd" />
                <text y={-17} textAnchor="middle" fill="#a2f7f4" fontSize={9}
                  fontWeight={700} letterSpacing={1.1} pointerEvents="none">
                  MONITORED SERVER
                </text>
                <text y={21} textAnchor="middle" fill="#9cb8bd" fontSize={8}
                  pointerEvents="none">
                  {target.serverId.slice(0, 24)}
                </text>
              </Marker>
            ))}

            {aggregateEvents.map((event, index) => {
              const location = targetPoint(event, configuredTarget);
              if (!location) return null;
              return (
                <Marker key={'aggregate-' + event.id} coordinates={location}>
                  <circle r={18 + index * 4} fill="none" stroke="#a78bfa" strokeWidth={1.4}
                    className="vanguard-aggregate-pulse" />
                  <text y={35 + index * 10} textAnchor="middle" fill="#c4b5fd" fontSize={8}
                    fontWeight={700} letterSpacing={0.8} pointerEvents="none">
                    ML AGGREGATE · {event.anomaly_score != null ? Math.round(event.anomaly_score) : '—'}
                  </text>
                </Marker>
              );
            })}
          </ZoomableGroup>
          </ComposableMap>

          {targets.length === 0 && (
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center p-4">
            <div className="rounded-lg border border-cyan-400/20 bg-[#08181e]/90 px-4 py-3 text-center text-xs text-slate-300">
              <MapPin className="mx-auto mb-1 h-4 w-4 text-cyan-300" aria-hidden="true" />
              {mapTargetLoading
                ? 'Loading monitored server location…'
                : 'Monitored server location unavailable. Configure destination coordinates to show request routes.'}
            </div>
          </div>
        )}

          {selected && (
          <section aria-label="Detection details"
            className="absolute right-3 top-3 z-20 w-[min(18rem,calc(100%-1.5rem))] rounded-lg border border-cyan-300/30 bg-[#091820]/95 p-3 text-[11px] text-slate-200 shadow-xl backdrop-blur-md">
            <div className="mb-2 flex items-start justify-between gap-2">
              <div>
                <p className="font-semibold uppercase tracking-wider text-cyan-200">
                  {detectionName(selected.event.attack_type)}
                </p>
                <p className="text-slate-400">Severity: {selected.event.severity} detection</p>
              </div>
              <button type="button" aria-label="Close detection details"
                onClick={() => setSelected(null)}
                className="rounded p-0.5 hover:bg-white/10 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-300">
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
            <dl className="grid grid-cols-[auto_1fr] gap-x-2 gap-y-1">
              <dt className="text-slate-400">Source</dt>
              <dd className="min-w-0 break-all">{selected.event.source_ip} · {selected.event.country || 'Unknown'}</dd>
              <dt className="text-slate-400">Server</dt>
              <dd className="min-w-0 break-all">{selected.event.server_id}</dd>
              <dt className="text-slate-400">Request</dt>
              <dd className="min-w-0 break-all">{selected.event.path
                ? (selected.event.method || 'HTTP') + ' ' + selected.event.path
                : 'Aggregated finding'}</dd>
              <dt className="text-slate-400">HTTP</dt>
              <dd>{selected.event.status_code ?? '—'}</dd>
              <dt className="text-slate-400">Time</dt>
              <dd>{new Date(selected.event.timestamp).toLocaleString()}</dd>
            </dl>
            <button onClick={() => inspectEvent(selected.event)} className="mt-3 min-h-10 rounded border border-cyan-300/30 px-3 text-cyan-200 hover:bg-white/10">Open investigation</button>
            <p className="mt-2 border-t border-cyan-300/10 pt-2 text-[10px] text-slate-400">
              Map locations are approximate; arcs are illustrative, not measured network paths.
            </p>
          </section>
          )}
        </div>
      </div>

      {showRecentDetections && (
        <div role="region" aria-label="Recent detections" className="relative z-10 shrink-0 overflow-hidden rounded-xl border border-[#1d3840] bg-[#071218]/95 shadow-[inset_0_0_30px_rgba(0,180,190,0.025)]">
          <div className="flex items-center justify-between gap-3 border-b border-[#1a323a] px-4 py-2">
            <div className="flex items-center gap-1 text-[10px] font-semibold tracking-widest text-cyan-200">
              <Info className="h-3 w-3" aria-hidden="true" />
              RECENT DETECTIONS · {recentDetections.length} SOURCES
            </div>
            <span className="hidden text-[10px] text-slate-500 sm:inline">Select a source to inspect its latest detection</span>
          </div>
          <div className="grid auto-cols-[minmax(180px,220px)] grid-flow-col gap-2 overflow-x-auto p-3">
            {events.length === 0 ? (
              <p className="py-2 text-xs text-slate-400">No detections recorded yet</p>
            ) : recentDetections.map(({ event, count }) => (
              <button key={event.id} type="button" onClick={() => showDetails(event, true)}
                className="min-h-[92px] rounded border border-[#1c3840] bg-[#0b1b23] p-2 text-left text-[10px] text-slate-300 transition-colors hover:border-cyan-300/50 hover:bg-[#102832] focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-300">
                <span className="flex items-center gap-1 font-semibold text-slate-100">
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full"
                    style={{ backgroundColor: severityColors[event.severity] || severityColors.low }} />
                  <span className="truncate">{event.country || 'Unknown'} · {detectionName(event.attack_type)}</span>
                </span>
                <span className="mt-1 block truncate text-slate-400">
                  {event.source_ip} → {event.server_id} · {eventTime(event.timestamp)}
                </span>
                <span className="mt-1 block truncate text-slate-400">#{event.id} · {event.path || 'Aggregated finding'}{!sourcePoint(event) || !targetPoint(event, configuredTarget) ? ' · Location unavailable' : ''}</span>
                <span className="mt-1 block text-cyan-200">{count} {count === 1 ? 'detection' : 'detections'} in recent events · latest shown</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
