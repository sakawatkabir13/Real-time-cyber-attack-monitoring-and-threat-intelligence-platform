import { describe, expect, it } from 'vitest';
import { advancePlayback, emptyPlayback, MAX_ACTIVE_ROUTES } from '@/components/mapPlayback';
import type { ThreatEvent } from '@/hooks/useThreatFeed';

describe('map playback', () => {
  it('keeps separate lanes stable for overlapping routes and reuses expired lanes', () => {
    const events = ['one', 'two', 'three', 'four'].map((id) => ({
      id, lat: 23.81, lng: 90.41, dest_lat: 39.05, dest_lng: -77.49,
    } as ThreatEvent));
    let state = advancePlayback({ ...emptyPlayback, pending: events }, 0);
    state = advancePlayback(state, 300);
    state = advancePlayback(state, 600);
    expect(state.active.map((route) => route.lane)).toEqual([0, 1, -1]);
    state = advancePlayback(state, 4200);
    expect(state.active.map((route) => [route.event.id, route.lane])).toEqual([
      ['two', 1], ['three', -1], ['four', 0],
    ]);
  });
  it('plays all 200 detections once in arrival order, without evicting overflow', () => {
    const burst = Array.from({ length: 200 }, (_, index) => ({ id: String(index) } as ThreatEvent));
    let state = { ...emptyPlayback, pending: burst };
    const started: string[] = [];
    for (let now = 0; now < 120000; now += 100) {
      const previousStart = state.lastStartedAt;
      state = advancePlayback(state, now);
      expect(state.active.length).toBeLessThanOrEqual(MAX_ACTIVE_ROUTES);
      if (state.lastStartedAt !== previousStart) started.push(state.active.at(-1)!.event.id);
    }
    expect(started).toEqual(burst.map((item) => item.id));
    expect(state.pending).toHaveLength(0);
    expect(state.active).toHaveLength(0);
  });
});
