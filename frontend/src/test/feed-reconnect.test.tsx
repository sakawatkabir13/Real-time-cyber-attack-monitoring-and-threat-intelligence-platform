import { act, renderHook, waitFor, cleanup } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { useThreatFeed, type ThreatEvent } from '@/hooks/useThreatFeed';
import { useAppStore } from '@/store/appStore';

const event: ThreatEvent = {
  id: 'one', server_id: 'spandan-web', source_ip: '203.0.113.1',
  dest_port: null, attack_type: 'scanner', severity: 'medium',
  country: 'BD', lat: null, lng: null, timestamp: '2026-09-29T10:00:00Z',
};

class TestSocket {
  static instances: TestSocket[] = [];
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onmessage: ((message: { data: string }) => void) | null = null;
  constructor(_url: string) { TestSocket.instances.push(this); }
  close() {}
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  TestSocket.instances = [];
});

describe('live event recovery', () => {
  it('backfills missed events on WebSocket open without dropping newer live events', async () => {
    useAppStore.setState((state) => ({
      settings: { ...state.settings, autoRefresh: true },
    }));
    let snapshot = [event];
    vi.stubGlobal('WebSocket', TestSocket);
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (url.startsWith('/api/events?ml_only=')) return new Response(JSON.stringify([]));
      if (url.startsWith('/api/events?')) return new Response(JSON.stringify(snapshot));
      if (url.startsWith('/api/alerts?')) return new Response(JSON.stringify([]));
      return new Response(JSON.stringify({ totalThreats: 1, attacksPerSecond: 0,
        criticalAlerts: 0, uniqueIPs: 1, topAttackTypes: [], threatsByHour: [] }));
    }));

    const { result } = renderHook(() => useThreatFeed());
    await waitFor(() => expect(result.current.events).toHaveLength(1));
    const newer = { ...event, id: 'live', timestamp: '2026-09-29T10:01:00Z' };
    act(() => TestSocket.instances[0].onmessage?.({
      data: JSON.stringify({ type: 'NEW_THREAT', data: newer }),
    }));
    snapshot = [{ ...event, id: 'missed', timestamp: '2026-09-29T10:00:30Z' }, event];
    act(() => TestSocket.instances[0].onopen?.());
    await waitFor(() => expect(result.current.events.map((item) => item.id))
      .toEqual(['live', 'missed', 'one']));
  });
});
