import type { ThreatEvent } from '@/hooks/useThreatFeed';

export const MAX_ACTIVE_ROUTES = 12;
export const ROUTE_LIFETIME_MS = 4200;
const ROUTE_SPACING_MS = 250;

export interface MapPlayback {
  active: { event: ThreatEvent; startedAt: number; lane: number }[];
  pending: ThreatEvent[];
  lastStartedAt: number;
}

export const emptyPlayback: MapPlayback = { active: [], pending: [], lastStartedAt: -Infinity };

// FIFO playback never evicts an unplayed event to make room for a new one.
// Staggering tracers makes repeat detections on the same route distinguishable.
export function advancePlayback(state: MapPlayback, now: number): MapPlayback {
  const active = state.active.filter((route) => now - route.startedAt < ROUTE_LIFETIME_MS);
  if (state.pending.length && active.length < MAX_ACTIVE_ROUTES &&
      now - state.lastStartedAt >= ROUTE_SPACING_MS) {
    const [event, ...pending] = state.pending;
    const sameRoute = (other: ThreatEvent) => other.lat === event.lat && other.lng === event.lng &&
      other.dest_lat === event.dest_lat && other.dest_lng === event.dest_lng;
    const occupied = new Set(active.filter((route) => sameRoute(route.event)).map((route) => route.lane));
    // Separate overlapping routes while keeping each lane stable until expiry.
    const lanes = Array.from({ length: MAX_ACTIVE_ROUTES * 2 + 1 }, (_, index) =>
      index === 0 ? 0 : Math.ceil(index / 2) * (index % 2 ? 1 : -1));
    const lane = lanes.find((candidate) => !occupied.has(candidate))!;
    return { active: [...active, { event, startedAt: now, lane }], pending, lastStartedAt: now };
  }
  return active.length === state.active.length ? state : { ...state, active };
}
