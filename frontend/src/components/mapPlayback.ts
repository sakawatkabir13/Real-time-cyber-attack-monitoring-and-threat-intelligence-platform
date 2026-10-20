import type { ThreatEvent } from '@/hooks/useThreatFeed';

export const ROUTE_LIFETIME_MS = 4200;

export interface LiveRoute {
  event: ThreatEvent;
  startedAt: number;
  lane: number;
}

// Receipt-time rendering, not FIFO playback. Every arrival starts immediately;
// only its short visual lifetime controls how long it remains on the map.
export class LiveMapRoutes {
  readonly active = new Map<string, LiveRoute>();
  private readonly seen = new Set<string>();
  private readonly groups = new Map<string, { next: number; count: number }>();
  private lastExpired = -Infinity;

  private key(event: ThreatEvent): string {
    return [event.lng, event.lat, event.dest_lng, event.dest_lat].join(':');
  }

  add(event: ThreatEvent, now: number): boolean {
    // requestAnimationFrame is suspended in hidden tabs; keep lifetime-based
    // memory cleanup running on arrivals there too, without replaying old arcs.
    if (now - this.lastExpired >= 1000) this.expire(now);
    if (this.seen.has(event.id) || this.active.has(event.id)) return false;
    this.seen.add(event.id);
    if (this.seen.size > 15000) this.seen.delete(this.seen.values().next().value!);
    const key = this.key(event);
    const group = this.groups.get(key) ?? { next: 0, count: 0 };
    // Reuse a bounded fan of lanes during large repeat-source bursts. This is
    // NOT a request limit: unlimited arrivals can share the same visible lane.
    const index = group.next++ % 9;
    const lane = index === 0 ? 0 : Math.ceil(index / 2) * (index % 2 ? 1 : -1);
    group.count += 1;
    this.groups.set(key, group);
    this.active.set(event.id, { event, startedAt: now, lane });
    return true;
  }

  expire(now: number): void {
    this.lastExpired = now;
    for (const [id, route] of this.active) {
      if (now - route.startedAt < ROUTE_LIFETIME_MS) continue;
      this.active.delete(id);
      const key = this.key(route.event);
      const group = this.groups.get(key)!;
      if (--group.count === 0) this.groups.delete(key);
    }
  }
}
