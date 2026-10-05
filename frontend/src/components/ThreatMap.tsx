import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent } from 'react';
import { geoInterpolate } from 'd3-geo';
import { Info, MapPin, Pause, Play, Radio, X } from 'lucide-react';
import { useInvestigation } from '@/components/EventInspector';
import { useReducedMotion } from 'framer-motion';
import { ComposableMap, Geographies, Geography, Line, Marker, ZoomableGroup } from 'react-simple-maps';
import countries from 'world-atlas/countries-110m.json';

import type { SubscribeToDetections, ThreatEvent } from '@/hooks/useThreatFeed';
import { advancePlayback, emptyPlayback } from './mapPlayback';
import { useAppStore } from '@/store/appStore';
import './ThreatMap.css';

interface ThreatMapProps {
  events: ThreatEvent[];
  liveEvent: ThreatEvent | null;
  subscribeToDetections?: SubscribeToDetections;
}

type GeoPoint = [number, number];

interface SelectedEvent {
  event: ThreatEvent;
  pinned: boolean;
}

const severityColors: Record<string, string> = {
  low: '#67e8f9',
  medium: '#fbbf24',
  high: '#fb923c',
  critical: '#fb4b62',
};

function point(lng: number | null | undefined, lat: number | null | undefined): GeoPoint | null {
  if (typeof lng !== 'number' || typeof lat !== 'number' ||
      !Number.isFinite(lng) || !Number.isFinite(lat) ||
      Math.abs(lng) > 180 || Math.abs(lat) > 90) return null;
  return [lng, lat];
}

function sourcePoint(event: ThreatEvent): GeoPoint | null {
  return point(event.lng, event.lat);
}

function targetPoint(event: ThreatEvent): GeoPoint | null {
  return point(event.dest_lng, event.dest_lat);
}

export function routeCoordinates(from: GeoPoint, to: GeoPoint): GeoPoint[] {
  const interpolate = geoInterpolate(from, to);
  return Array.from({ length: 49 }, (_, index) =>
    index === 0 ? from : index === 48 ? to : interpolate(index / 48) as GeoPoint);
}

function detectionName(value: string): string {
  return value.replace(/_/g, ' ');
}

function eventTime(value: string): string {
  return new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export default function ThreatMap({ events, liveEvent, subscribeToDetections }: ThreatMapProps) {
  const { inspectEvent } = useInvestigation();
  const [playback, setPlayback] = useState(emptyPlayback);
  const [selected, setSelected] = useState<SelectedEvent | null>(null);
  const [paused, setPaused] = useState(false);
  const seenIds = useRef(new Set<string>());
  const reducedMotion = useReducedMotion();
  const autoRefresh = useAppStore((state) => state.settings.autoRefresh);
  const animationsEnabled = !paused && !reducedMotion;

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

  const targets = useMemo(() => {
    const byServer = new Map<string, { serverId: string; coordinates: GeoPoint }>();
    for (const event of [liveEvent, ...events]) {
      if (!event || byServer.has(event.server_id)) continue;
      const coordinates = targetPoint(event);
      if (coordinates) byServer.set(event.server_id, { serverId: event.server_id, coordinates });
      if (byServer.size >= 4) break;
    }
    return [...byServer.values()];
  }, [events, liveEvent]);

  const enqueueDetection = useCallback((event: ThreatEvent) => {
    if (seenIds.current.has(event.id)) return;
    seenIds.current.add(event.id);
    // Bound the replay guard, not the playback queue. Pending IDs are also checked below.
    if (seenIds.current.size > 5000) seenIds.current.delete(seenIds.current.values().next().value!);
    if (reducedMotion || !sourcePoint(event) || !targetPoint(event)) return;
    setPlayback((current) => {
      if (current.pending.some((item) => item.id === event.id) ||
          current.active.some((route) => route.event.id === event.id)) return current;
      return { ...current, pending: [...current.pending, event] };
    });
  }, [reducedMotion]);

  useEffect(() => subscribeToDetections?.(enqueueDetection), [subscribeToDetections, enqueueDetection]);

  useEffect(() => {
    if (!subscribeToDetections && liveEvent) enqueueDetection(liveEvent);
  }, [liveEvent, subscribeToDetections, enqueueDetection]);

  useEffect(() => {
    if (!animationsEnabled) return;
    const startedAt = Date.now();
    setPlayback((current) => advancePlayback(current, startedAt));
    const timer = window.setInterval(() => {
      const now = Date.now();
      setPlayback((current) => advancePlayback(current, now));
    }, 100);
    return () => window.clearInterval(timer);
  }, [animationsEnabled, playback.pending.length]);

  const togglePaused = () => {
    if (!paused) {
      // Restart any interrupted route on resume, rather than losing it while hidden.
      setPlayback((current) => ({ ...emptyPlayback,
        pending: [...current.active.map((route) => route.event), ...current.pending] }));
    }
    setPaused((current) => !current);
  };

  const showDetails = (event: ThreatEvent, pinned: boolean) => setSelected({ event, pinned });
  const hideUnpinned = () => setSelected((current) => current?.pinned ? current : null);
  const onMarkerKeyDown = (keyEvent: KeyboardEvent<SVGCircleElement>, event: ThreatEvent) => {
    if (keyEvent.key === 'Enter' || keyEvent.key === ' ') {
      keyEvent.preventDefault();
      showDetails(event, true);
    }
  };

  return (
    <div className="vanguard-map relative flex h-full min-h-[400px] flex-col overflow-hidden rounded-xl border border-[#1d3840] bg-[#061016] shadow-[inset_0_0_60px_rgba(0,180,190,0.035)]">
      <div className="relative z-10 flex flex-wrap items-center justify-between gap-2 border-b border-[#1a323a] bg-[#071218]/95 px-4 py-3">
        <div className="flex items-center gap-3">
          <Radio className="h-4 w-4 text-cyan-300" aria-hidden="true" />
          <div>
            <h2 className="text-xs font-bold tracking-[0.18em] text-slate-100">LIVE DETECTION MAP</h2>
            <p className="text-[10px] text-slate-400">HTTP detections · approximate locations · illustrative routes</p>
          </div>
          <span className="rounded-full border border-emerald-400/25 bg-emerald-400/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-300">
            {autoRefresh ? 'AUTO REFRESH ON' : 'AUTO REFRESH OFF'}
          </span>
        </div>
        <div className="flex items-center gap-3">
          <div className="hidden items-center gap-2 text-[10px] text-slate-300 sm:flex" aria-label="Detection severity legend">
            {(['low', 'medium', 'high', 'critical'] as const).map((severity) => (
              <span key={severity} className="flex items-center gap-1 capitalize">
                <span className="h-2 w-2 rounded-full" style={{ backgroundColor: severityColors[severity] }} />
                {severity}
              </span>
            ))}
          </div>
          <button
            type="button"
            aria-label={paused ? 'Resume map animations' : 'Pause map animations'}
            aria-pressed={paused}
            disabled={Boolean(reducedMotion)}
            title={reducedMotion ? 'Animations disabled by system reduced-motion preference' : undefined}
            onClick={togglePaused}
            className="inline-flex items-center gap-1 rounded border border-[#31505a] px-2 py-1 text-[10px] text-slate-200 transition-colors hover:bg-white/10 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-300 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {paused ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />}
            {reducedMotion ? 'Reduced motion' : paused ? 'Resume animation' : 'Pause animation'}
          </button>
        </div>
      </div>

      <div className="vanguard-map-surface relative min-h-[230px] flex-1">
        <div className="pointer-events-none absolute left-3 top-3 z-10 rounded border border-cyan-300/20 bg-[#071218]/90 px-2 py-1 text-[10px] text-cyan-100">
          {playback.active.length} animating · {playback.pending.length} queued
          {playback.pending.length > 0 && <span className="block text-slate-400">{paused ? 'Paused — detections retained' : 'Queued playback — not real-time packet timing'}</span>}
          {events.some((event) => !sourcePoint(event) || !targetPoint(event)) &&
            <span className="block text-amber-200">Some detections lack location data; see cards below</span>}
        </div>
        <ComposableMap width={1000} height={400} projection="geoMercator"
          projectionConfig={{ scale: 155 }} className="h-full w-full">
          <ZoomableGroup center={[0, 5]} zoom={1} minZoom={1} maxZoom={4}>
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

            {animationsEnabled && playback.active.map(({ event }, index) => {
              const from = sourcePoint(event);
              const to = targetPoint(event);
              if (!from || !to) return null;
              const coordinates = routeCoordinates(from, to);
              const color = severityColors[event.severity] || severityColors.low;
              return (
                <g key={'route-' + event.id} data-event-id={event.id} pointerEvents="none">
                  <Line data-testid="threat-arc" from={from} to={to} coordinates={coordinates}
                    pathLength={1} stroke={color} strokeWidth={1.4}
                    className="vanguard-route-path" />
                  <Line data-testid="route-tracer" from={from} to={to} coordinates={coordinates}
                    pathLength={1} stroke={color} strokeWidth={3.2}
                    className="vanguard-route-tracer" style={{ color }} />
                  <Marker coordinates={from}>
                    <circle r={4} fill="none" stroke={color} strokeWidth={1}
                      className="vanguard-source-flash" />
                    <text x={7} y={10 + (index % 4) * 10} fill={color} fontSize={8}>#{event.id}</text>
                  </Marker>
                  <Marker coordinates={to}>
                    <circle r={5} fill="none" stroke={color} strokeWidth={1.3}
                      className="vanguard-target-pulse" />
                  </Marker>
                </g>
              );
            })}

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
          </ZoomableGroup>
        </ComposableMap>

        {targets.length === 0 && (
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center p-4">
            <div className="rounded-lg border border-cyan-400/20 bg-[#08181e]/90 px-4 py-3 text-center text-xs text-slate-300">
              <MapPin className="mx-auto mb-1 h-4 w-4 text-cyan-300" aria-hidden="true" />
              Monitored server location unavailable. Add destination coordinates to show request routes.
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

      <div className="relative z-10 flex min-h-[68px] items-center gap-3 border-t border-[#1a323a] bg-[#071218]/95 px-4 py-2">
        <div className="hidden shrink-0 items-center gap-1 text-[10px] font-semibold tracking-widest text-cyan-200 md:flex">
          <Info className="h-3 w-3" aria-hidden="true" />
          RECENT {events.length} DETECTIONS
        </div>
        <div className="flex min-w-0 flex-1 gap-2 overflow-x-auto">
          {events.length === 0 ? (
            <p className="py-2 text-xs text-slate-400">No detections recorded yet</p>
          ) : events.map((event) => (
            <button key={event.id} type="button" onClick={() => showDetails(event, true)}
              className="min-w-[175px] flex-1 rounded border border-[#1c3840] bg-[#0b1b23] px-2 py-1.5 text-left text-[10px] text-slate-300 transition-colors hover:border-cyan-300/40 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-300">
              <span className="flex items-center gap-1 font-semibold text-slate-100">
                <span className="h-1.5 w-1.5 rounded-full"
                  style={{ backgroundColor: severityColors[event.severity] || severityColors.low }} />
                {event.country || 'Unknown'} · {detectionName(event.attack_type)}
              </span>
              <span className="mt-1 block truncate text-slate-400">
                {event.source_ip} → {event.server_id} · {eventTime(event.timestamp)}
              </span>
              <span className="block truncate text-slate-400">#{event.id} · {event.path || 'Aggregated finding'}{!sourcePoint(event) || !targetPoint(event) ? ' · Location unavailable' : ''}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
