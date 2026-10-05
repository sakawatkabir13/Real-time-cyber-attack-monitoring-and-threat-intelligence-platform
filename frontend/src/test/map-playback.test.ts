import { describe, expect, it } from 'vitest';
import { advancePlayback, emptyPlayback, MAX_ACTIVE_ROUTES } from '@/components/mapPlayback';
import type { ThreatEvent } from '@/hooks/useThreatFeed';

describe('map playback', () => {
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
