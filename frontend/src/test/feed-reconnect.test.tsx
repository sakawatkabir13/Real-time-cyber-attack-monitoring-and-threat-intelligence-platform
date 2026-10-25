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
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
  TestSocket.instances = [];
});

describe('live event recovery', () => {
  it('retries unavailable map configuration on reconnect and exposes the error', async () => {
    useAppStore.setState((state) => ({ settings: { ...state.settings, autoRefresh: true } }));
    vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.stubGlobal('WebSocket', TestSocket);
    let mapRequests = 0;
    const target = { serverId: 'spandan-web', lat: 39.05, lng: -77.49 };
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (url.startsWith('/api/map-config')) {
        mapRequests += 1;
        return mapRequests === 1 ? new Response('{}', { status: 503 })
          : new Response(JSON.stringify({ target }));
      }
      return new Response(JSON.stringify([]));
    }));
    const { result } = renderHook(() => useThreatFeed());
    await waitFor(() => expect(result.current.error).toContain('Map configuration unavailable (503)'));
    expect(result.current.mapTargetLoading).toBe(false);
    act(() => TestSocket.instances[0].onopen?.());
    await waitFor(() => expect(result.current.mapTarget).toEqual(target));
    expect(result.current.error).toBe('');
  });

  it('retains a good map destination during failed refreshes and retries periodically', async () => {
    useAppStore.setState((state) => ({ settings: { ...state.settings, autoRefresh: true } }));
    vi.useFakeTimers();
    vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.stubGlobal('WebSocket', TestSocket);
    const target = { serverId: 'spandan-web', lat: 39.05, lng: -77.49 };
    let failing = false;
    const fetchMock = vi.fn(async (url: string) => {
      if (url.startsWith('/api/map-config')) return failing ? new Response('{}', { status: 503 })
        : new Response(JSON.stringify({ target }));
      return new Response(JSON.stringify([]));
    });
    vi.stubGlobal('fetch', fetchMock);
    const { result } = renderHook(() => useThreatFeed());
    await act(async () => {});
    expect(result.current.mapTarget).toEqual(target);
    failing = true;
    await act(async () => { TestSocket.instances[0].onopen?.(); });
    expect(result.current.error).toContain('Map configuration unavailable (503)');
    expect(result.current.mapTarget).toEqual(target);
    failing = false;
    await act(async () => { await vi.advanceTimersByTimeAsync(30000); });
    expect(result.current.error).toBe('');
    expect(result.current.mapTarget).toEqual(target);
    expect(fetchMock.mock.calls.filter(([url]) => url.startsWith('/api/map-config'))).toHaveLength(3);
  });

  it('animates requests received during initial connection setup but not older history', async () => {
    useAppStore.setState((state) => ({ settings: { ...state.settings, autoRefresh: true } }));
    vi.stubGlobal('WebSocket', TestSocket);
    let finishSnapshot!: (response: Response) => void;
    const snapshot = new Promise<Response>((resolve) => { finishSnapshot = resolve; });
    vi.stubGlobal('fetch', vi.fn(async (url: string) => url.startsWith('/api/traffic?')
      ? snapshot : new Response(JSON.stringify([]))));
    const { result } = renderHook(() => useThreatFeed());
    const received: string[] = [];
    result.current.subscribeToTraffic((item) => received.push(item.id));
    const fresh = { ...event, id: 'http:during-connect', severity: 'normal', timestamp: new Date().toISOString() };
    await act(async () => { finishSnapshot(new Response(JSON.stringify([fresh, event]))); });
    expect(received).toEqual(['http:during-connect']);
    expect(result.current.trafficEvents).toHaveLength(2);
    act(() => TestSocket.instances[0].onmessage?.({ data: JSON.stringify({ type: 'HTTP_TRAFFIC', data: [fresh] }) }));
    expect(received).toEqual(['http:during-connect']);
  });
  it('delivers every normal and suspicious HTTP request without adding either to detection history', async () => {
    useAppStore.setState((state) => ({ settings: { ...state.settings, autoRefresh: true } }));
    vi.stubGlobal('WebSocket', TestSocket);
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify([]))));
    const { result } = renderHook(() => useThreatFeed({ serverId: 'spandan-web' }));
    await act(async () => {});
    const received: string[] = [];
    result.current.subscribeToTraffic((item) => received.push(item.id));
    const traffic = Array.from({ length: 200 }, (_, index) => ({ ...event, id: `http:${index}`,
      kind: 'http_request', severity: index % 2 ? 'medium' : 'normal' }));
    act(() => {
      TestSocket.instances[0].onmessage?.({ data: JSON.stringify({ type: 'HTTP_TRAFFIC', data: traffic }) });
      TestSocket.instances[0].onmessage?.({ data: JSON.stringify({ type: 'HTTP_TRAFFIC', data: traffic }) });
      TestSocket.instances[0].onmessage?.({ data: JSON.stringify({ type: 'HTTP_TRAFFIC', data: [{ ...traffic[0], id: 'other', server_id: 'other' }] }) });
    });
    expect(received).toEqual(traffic.map((item) => item.id));
    expect(result.current.trafficEvents).toHaveLength(200);
    expect(result.current.liveTrafficEvent?.id).toBe('http:199');
    expect(result.current.events).toHaveLength(0);
    expect(result.current.mlEvents).toHaveLength(0);
  });

  it('recovers missed HTTP traffic once on reconnect without animating the initial history', async () => {
    useAppStore.setState((state) => ({ settings: { ...state.settings, autoRefresh: true } }));
    vi.stubGlobal('WebSocket', TestSocket);
    const history = { ...event, id: 'http:history', kind: 'http_request', severity: 'normal' };
    const missed = { ...history, id: 'http:missed', timestamp: '2026-09-29T10:01:00Z' };
    let snapshot = [history];
    vi.stubGlobal('fetch', vi.fn(async (url: string) => new Response(JSON.stringify(
      url.startsWith('/api/traffic?') ? snapshot : [],
    ))));
    const { result } = renderHook(() => useThreatFeed());
    await waitFor(() => expect(result.current.trafficEvents).toHaveLength(1));
    expect(result.current.liveTrafficEvent).toBeNull();
    const received: string[] = [];
    result.current.subscribeToTraffic((item) => received.push(item.id));
    snapshot = [missed, history];
    act(() => TestSocket.instances[0].onopen?.());
    await waitFor(() => expect(received).toEqual(['http:missed']));
    act(() => TestSocket.instances[0].onopen?.());
    await act(async () => {});
    expect(received).toEqual(['http:missed']);
  });
  it('delivers every WebSocket detection even when React batches the latest-event state', async () => {
    useAppStore.setState((state) => ({ settings: { ...state.settings, autoRefresh: true } }));
    vi.stubGlobal('WebSocket', TestSocket);
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify([]))));
    const { result } = renderHook(() => useThreatFeed());
    await act(async () => {});
    const received: string[] = [];
    const unsubscribe = result.current.subscribeToDetections((item) => received.push(item.id));
    act(() => {
      for (let index = 0; index < 200; index += 1) {
        TestSocket.instances[0].onmessage?.({
          data: JSON.stringify({ type: 'NEW_THREAT', data: { ...event, id: String(index) } }),
        });
      }
    });
    expect(received).toEqual(Array.from({ length: 200 }, (_, index) => String(index)));
    expect(result.current.liveEvent?.id).toBe('199');
    unsubscribe();
    act(() => TestSocket.instances[0].onmessage?.({ data: JSON.stringify({ type: 'NEW_THREAT', data: event }) }));
    expect(received).toHaveLength(200);
  });
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
