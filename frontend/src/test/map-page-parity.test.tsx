import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import Dashboard from '@/pages/Dashboard';
import MapPage from '@/pages/MapPage';
import { useDetectionViewStore } from '@/store/detectionViewStore';
import type { ThreatEvent } from '@/hooks/useThreatFeed';

const feed = vi.hoisted(() => vi.fn());
vi.mock('@/hooks/useThreatFeed', () => ({ useThreatFeed: feed }));
vi.mock('@/components/ThreatMap', () => ({ default: ({ events, ...options }: { events: ThreatEvent[] }) =>
  <output data-testid="map-input">{JSON.stringify({ events, options })}</output> }));
vi.mock('@/components/CollectorControl', () => ({ default: () => null }));
vi.mock('@/components/ThreatCharts', () => ({ default: () => null }));
vi.mock('@/components/AnomalyChart', () => ({ default: () => null }));
vi.mock('@/components/LiveEventFeed', () => ({ default: () => null }));
vi.mock('@/components/AlertQueue', () => ({ default: () => null }));
vi.mock('@/components/StatCard', () => ({ default: () => null }));
vi.mock('@/components/ThreatTable', () => ({ default: () => null }));
vi.mock('@/components/FeedStatus', () => ({ default: () => null }));

beforeEach(() => {
  useDetectionViewStore.setState({ hours: 24, serverId: '' });
  feed.mockReset().mockImplementation(({ hours, serverId }) => ({
    events: [{ id: `${hours}:${serverId}`, source_ip: '203.0.113.7' }], mlEvents: [],
    stats: { attacksPerSecond: 0, criticalAlerts: 0, uniqueIPs: 1, totalThreats: 1 },
    liveEvent: null, subscribeToDetections: () => () => {},
    connection: 'live', updatedAt: null, error: '', refresh: () => {},
  }));
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify([
    { serverId: 'spandan-web' }, { serverId: 'other-web' },
  ]))));
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); useDetectionViewStore.setState({ hours: 24, serverId: '' }); });

const assertSameMaps = () => {
  const maps = screen.getAllByTestId('map-input');
  expect(maps).toHaveLength(2);
  expect(maps[0].textContent).toBe(maps[1].textContent);
};

describe('Dashboard and Threat Map parity', () => {
  it('uses the same default scope and updates both map inputs when either page changes filters', async () => {
    render(<><Dashboard /><MapPage /></>);
    assertSameMaps();
    expect(feed).toHaveBeenCalledWith({ hours: 24, serverId: '' });
    await waitFor(() => expect(screen.getAllByRole('option', { name: 'spandan-web' })).toHaveLength(2));
    fireEvent.change(screen.getAllByRole('combobox', { name: 'Detection period' })[0], { target: { value: '168' } });
    expect(screen.getAllByRole('combobox', { name: 'Detection period' }).every((select) => (select as HTMLSelectElement).value === '168')).toBe(true);
    fireEvent.change(screen.getAllByRole('combobox', { name: 'Detection server' })[1], { target: { value: 'spandan-web' } });
    expect(feed.mock.calls.slice(-2).map(([scope]) => scope)).toEqual([
      { hours: 168, serverId: 'spandan-web' }, { hours: 168, serverId: 'spandan-web' },
    ]);
    assertSameMaps();
  });

  it('preserves only filter choices across full-page navigation', async () => {
    render(<Dashboard />);
    act(() => { useDetectionViewStore.getState().setHours(1); useDetectionViewStore.getState().setServerId('spandan-web'); });
    const saved = localStorage.getItem('vanguard-detection-view')!;
    expect(JSON.parse(saved).state).toEqual({ hours: 1, serverId: 'spandan-web' });
    cleanup();
    useDetectionViewStore.setState({ hours: 24, serverId: '' });
    localStorage.setItem('vanguard-detection-view', saved);
    await act(async () => { await useDetectionViewStore.persist.rehydrate(); });
    render(<MapPage />);
    await waitFor(() => expect(screen.getByRole('option', { name: 'other-web' })).toBeInTheDocument());
    expect(screen.getByRole('combobox', { name: 'Detection period' })).toHaveValue('1');
    expect(screen.getByRole('combobox', { name: 'Detection server' })).toHaveValue('spandan-web');
    expect(feed).toHaveBeenLastCalledWith({ hours: 1, serverId: 'spandan-web' });
  });

  it('synchronizes filter choices changed in another browser tab', async () => {
    render(<><Dashboard /><MapPage /></>);
    localStorage.setItem('vanguard-detection-view', JSON.stringify({ state: { hours: 1, serverId: 'other-web' }, version: 0 }));
    await act(async () => { window.dispatchEvent(new StorageEvent('storage', { key: 'vanguard-detection-view' })); });
    expect(screen.getAllByRole('combobox', { name: 'Detection period' }).every((select) => (select as HTMLSelectElement).value === '1')).toBe(true);
    expect(screen.getAllByRole('combobox', { name: 'Detection server' }).every((select) => (select as HTMLSelectElement).value === 'other-web')).toBe(true);
    assertSameMaps();
  });

  it('rejects invalid stored filters rather than loading a different unbounded scope', async () => {
    localStorage.setItem('vanguard-detection-view', JSON.stringify({ state: { hours: 9999, serverId: {} }, version: 0 }));
    await act(async () => { await useDetectionViewStore.persist.rehydrate(); });
    expect(useDetectionViewStore.getState().hours).toBe(24);
    expect(useDetectionViewStore.getState().serverId).toBe('');
  });
});
