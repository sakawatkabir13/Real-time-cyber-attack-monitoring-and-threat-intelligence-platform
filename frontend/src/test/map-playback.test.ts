import { describe, expect, it } from 'vitest';
import { LiveMapRoutes, ROUTE_LIFETIME_MS } from '@/components/mapPlayback';
import type { ThreatEvent } from '@/hooks/useThreatFeed';

function event(id: string): ThreatEvent {
  return { id, timestamp: id, lat: 23.81, lng: 90.41, dest_lat: 39.05, dest_lng: -77.49 } as ThreatEvent;
}

describe('immediate live map routes', () => {
  it('starts all 1000 arrivals immediately, regardless of differing event timestamps', () => {
    const state = new LiveMapRoutes();
    for (let index = 0; index < 1000; index += 1) expect(state.add(event(String(index)), 100)).toBe(true);
    expect(state.active.size).toBe(1000);
    expect(new Set([...state.active.values()].map((route) => route.startedAt))).toEqual(new Set([100]));
    expect('pending' in state).toBe(false);
  });
  it('never delays a new arrival while older arcs are still visible', () => {
    const state = new LiveMapRoutes();
    state.add(event('old'), 0);
    state.add(event('new'), 1);
    expect([...state.active.values()].map((route) => route.startedAt)).toEqual([0, 1]);
    state.expire(ROUTE_LIFETIME_MS);
    expect([...state.active.keys()]).toEqual(['new']);
    state.expire(ROUTE_LIFETIME_MS + 1);
    expect(state.active.size).toBe(0);
  });
  it('deduplicates recovery deliveries without restarting expired requests', () => {
    const state = new LiveMapRoutes();
    expect(state.add(event('one'), 0)).toBe(true);
    expect(state.add(event('one'), 100)).toBe(false);
    state.expire(10000);
    expect(state.add(event('one'), 10000)).toBe(false);
  });
  it('bounds lane curvature, not the number of simultaneous requests', () => {
    const state = new LiveMapRoutes();
    for (let index = 0; index < 1000; index += 1) state.add(event(String(index)), 0);
    const lanes = [...state.active.values()].map((route) => route.lane);
    expect(lanes.slice(0, 5)).toEqual([0, 1, -1, 2, -2]);
    expect(Math.max(...lanes.map(Math.abs))).toBe(4);
    expect(state.active.size).toBe(1000);
    state.expire(10000);
    state.add(event('fresh'), 10000);
    expect(state.active.get('fresh')?.lane).toBe(0);
  });
  it('expires old traffic on receipt even while a background tab is not drawing', () => {
    const state = new LiveMapRoutes();
    for (let index = 0; index < 20; index += 1) state.add(event(String(index)), index * 1000);
    expect([...state.active.values()].every((route) => route.startedAt >= 15000)).toBe(true);
    state.expire(25000);
    expect(state.active.size).toBe(0);
  });
});
