import type { ThreatEvent } from '@/hooks/useThreatFeed';

export const MAX_ACTIVE_ROUTES = 12;
export const ROUTE_LIFETIME_MS = 4200;
const ROUTE_SPACING_MS = 250;

export interface MapPlayback {
  active: { event: ThreatEvent; startedAt: number }[];
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
    return { active: [...active, { event, startedAt: now }], pending, lastStartedAt: now };
  }
  return active.length === state.active.length ? state : { ...state, active };
}
