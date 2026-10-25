import type { ThreatEvent } from '@/hooks/useThreatFeed';

export const MAX_ACTIVE_ROUTES = 96;
// A browser visualization is not an access-log archive. Bound queued animation
// work during overload (or a long pause), and report every omitted animation.
export const MAX_PENDING_ROUTES = 1000;
export const ROUTE_LIFETIME_MS = 4200;
// Timestamp-matched demo bursts start together. Different timestamps retain a
// small stagger so ordinary live traffic does not overwhelm the map.
const ROUTE_SPACING_MS = 80;

export interface MapPlayback {
  active: { event: ThreatEvent; startedAt: number; lane: number }[];
  pending: ThreatEvent[];
  lastStartedAt: number;
  omittedRoutes: number;
}

export const emptyPlayback: MapPlayback = { active: [], pending: [], lastStartedAt: -Infinity, omittedRoutes: 0 };

function boundedPending(state: MapPlayback, pending: ThreatEvent[]): MapPlayback {
  const overflow = Math.max(0, pending.length - MAX_PENDING_ROUTES);
  return { ...state, pending: overflow ? pending.slice(overflow) : pending,
    omittedRoutes: state.omittedRoutes + overflow };
}

export function enqueueRoute(state: MapPlayback, event: ThreatEvent): MapPlayback {
  if (state.pending.some((item) => item.id === event.id) ||
      state.active.some((route) => route.event.id === event.id)) return state;
  return boundedPending(state, [...state.pending, event]);
}

export function pausePlayback(state: MapPlayback): MapPlayback {
  // Resume interrupted routes in FIFO order. The same overload bound applies
  // when active routes are returned to a full queue.
  return boundedPending({ ...emptyPlayback, omittedRoutes: state.omittedRoutes },
    [...state.active.map((route) => route.event), ...state.pending]);
}

// FIFO playback retains its order within the bounded visualization backlog.
// Events sharing one timestamp start in the same frame, producing the
// simultaneous multi-origin fan used by the demonstration. Untimestamped
// test/legacy records use the ordinary staggered path.
export function advancePlayback(state: MapPlayback, now: number): MapPlayback {
  const active = state.active.filter((route) => now - route.startedAt < ROUTE_LIFETIME_MS);
  if (!state.pending.length || active.length >= MAX_ACTIVE_ROUTES) {
    return active.length === state.active.length ? state : { ...state, active };
  }

  const first = state.pending[0];
  const timestamped = typeof first.timestamp === 'string' && first.timestamp.length > 0;
  const burstInProgress = timestamped && active.some((route) => route.event.timestamp === first.timestamp);
  if (!burstInProgress && now - state.lastStartedAt < ROUTE_SPACING_MS) {
    return active.length === state.active.length ? state : { ...state, active };
  }

  // Take the contiguous timestamp-matched prefix so a synchronized batch is
  // launched in one state update. Events with missing timestamps remain FIFO.
  let burstLength = 1;
  if (timestamped) {
    while (burstLength < state.pending.length &&
      state.pending[burstLength].timestamp === first.timestamp) burstLength += 1;
  }
  const count = Math.min(burstLength, MAX_ACTIVE_ROUTES - active.length);
  const batch = state.pending.slice(0, count);
  const pending = state.pending.slice(count);
  const lanes = Array.from({ length: MAX_ACTIVE_ROUTES * 2 + 1 }, (_, index) =>
    index === 0 ? 0 : Math.ceil(index / 2) * (index % 2 ? 1 : -1));
  const startedSoFar: { event: ThreatEvent; lane: number }[] = [];
  const started = batch.map((event) => {
    const sameRoute = (other: ThreatEvent) => other.lat === event.lat && other.lng === event.lng &&
      other.dest_lat === event.dest_lat && other.dest_lng === event.dest_lng;
    const occupied = new Set(active.filter((route) => sameRoute(route.event)).map((route) => route.lane));
    const alreadyAssigned = startedLanes(startedSoFar, sameRoute);
    const lane = lanes.find((candidate) => !occupied.has(candidate) && !alreadyAssigned.has(candidate))!;
    startedSoFar.push({ event, lane });
    return { event, startedAt: now, lane };
  });
  return { ...state, active: [...active, ...started], pending, lastStartedAt: now };
}

function startedLanes(
  started: { event: ThreatEvent; lane: number }[],
  sameRoute: (event: ThreatEvent) => boolean,
): Set<number> {
  return new Set(started.filter((route) => sameRoute(route.event)).map((route) => route.lane));
}
