import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { geoEqualEarth, geoPath } from 'd3-geo';

import ThreatMap, { routeCoordinates } from '@/components/ThreatMap';
import type { ThreatEvent } from '@/hooks/useThreatFeed';

const reducedMotion = vi.hoisted(() => vi.fn(() => false));

vi.mock('react-simple-maps', () => ({
  ComposableMap: ({ children, projection, projectionConfig, width, height }: {
    children: ReactNode; projection: string; projectionConfig: { scale: number }; width: number; height: number;
  }) => <svg data-testid="map-projection" data-projection={projection} data-scale={projectionConfig.scale}
    data-width={width} data-height={height}>{children}</svg>,
  ZoomableGroup: ({ children }: { children: ReactNode }) => <g>{children}</g>,
  Geographies: ({ children }: { children: (value: { geographies: [] }) => ReactNode }) =>
    <g>{children({ geographies: [] })}</g>,
  Geography: () => <g />,
  Marker: ({ coordinates, children }: { coordinates: number[]; children: ReactNode }) =>
    <g data-coordinates={coordinates.join(',')}>{children}</g>,
  Line: ({ from, to, coordinates, ...props }: {
    from: number[]; to: number[]; coordinates: number[][]; 'data-testid': string;
  }) => <path data-testid={props['data-testid']} data-from={from.join(',')}
    data-to={to.join(',')} data-samples={coordinates.length} />,
}));

vi.mock('framer-motion', () => ({ useReducedMotion: reducedMotion }));

function event(id: string, lat: number, lng: number): ThreatEvent {
  return {
    id,
    server_id: 'spandan-web',
    source_ip: id,
    dest_port: null,
    method: 'GET',
    path: '/admin',
    status_code: 404,
    attack_type: 'scanner',
    severity: 'medium',
    country: 'BD',
    lat,
    lng,
    dest_lat: 39.0469,
    dest_lng: -77.4903,
    timestamp: '2026-09-29T00:00:00Z',
  };
}

beforeEach(() => { reducedMotion.mockReturnValue(false); vi.useFakeTimers(); });
afterEach(() => { cleanup(); vi.useRealTimers(); });

describe('ThreatMap precision routes', () => {
  it('frames the full world so long northern arcs cannot leave the default viewport', () => {
    render(<ThreatMap events={[]} liveEvent={null} />);
    const map = screen.getByTestId('map-projection');
    expect(map).toHaveAttribute('data-projection', 'geoEqualEarth');
    const width = Number(map.getAttribute('data-width'));
    const height = Number(map.getAttribute('data-height'));
    const projection = geoEqualEarth().scale(Number(map.getAttribute('data-scale'))).translate([width / 2, height / 2]);
    const [[left, top], [right, bottom]] = geoPath(projection).bounds({ type: 'Sphere' });
    expect(left).toBeGreaterThan(0);
    expect(top).toBeGreaterThan(0);
    expect(right).toBeLessThan(width);
    expect(bottom).toBeLessThan(height);
  });
  it('routes independent live sources to their monitored server, never to each other', () => {
    const bangladesh = event('bd', 23.81, 90.41);
    const germany = event('de', 52.52, 13.405);
    const view = render(<ThreatMap events={[bangladesh, germany]} liveEvent={bangladesh} />);
    view.rerender(<ThreatMap events={[germany, bangladesh]} liveEvent={germany} />);
    act(() => vi.advanceTimersByTime(300));

    expect(screen.getByText('MONITORED SERVER').parentElement)
      .toHaveAttribute('data-coordinates', '-77.4903,39.0469');
    const arcs = screen.getAllByTestId('threat-arc');
    expect(arcs).toHaveLength(2);
    expect(arcs.map((arc) => arc.getAttribute('data-from')))
      .toEqual(['90.41,23.81', '13.405,52.52']);
    expect(arcs.map((arc) => arc.getAttribute('data-to')))
      .toEqual(['-77.4903,39.0469', '-77.4903,39.0469']);
    expect(arcs[0]).toHaveAttribute('data-samples', '49');
    expect(screen.getAllByTestId('route-tracer')).toHaveLength(2);
  });

  it('samples a curved geodesic rather than a straight two-point line', () => {
    const points = routeCoordinates([13.405, 52.52], [-77.4903, 39.0469]);
    expect(points).toHaveLength(49);
    expect(points[0]).toEqual([13.405, 52.52]);
    expect(points[48]).toEqual([-77.4903, 39.0469]);
    expect(points[24][1]).toBeGreaterThan((52.52 + 39.0469) / 2);
  });

  it('separates repeat-source arcs into lanes without changing their endpoints', () => {
    const from: [number, number] = [90.41, 23.81];
    const to: [number, number] = [-77.4903, 39.0469];
    const paths = [0, 1, -1].map((lane) => routeCoordinates(from, to, lane));
    for (const path of paths) {
      expect(path[0]).toEqual(from);
      expect(path[48]).toEqual(to);
      expect(path.every(([lng, lat]) => Number.isFinite(lng) && Math.abs(lng) <= 180 && Math.abs(lat) <= 90)).toBe(true);
    }
    expect(new Set(paths.map((path) => JSON.stringify(path[24]))).size).toBe(3);
    // North/south routes also need separation, not just horizontal ones.
    expect(routeCoordinates([0, -30], [0, 30], 1)[24][0]).not.toBe(0);
  });

  it('shows unique source cards inside the map while animating all three repeated requests', () => {
    const first = { ...event('one', 23.81, 90.41), source_ip: '103.1.2.3', path: '/first' };
    const second = { ...first, id: 'two', path: '/second' };
    const third = { ...first, id: 'three', path: '/latest' };
    const other = { ...event('other', 52.52, 13.4), source_ip: '198.51.100.2' };
    const view = render(<ThreatMap events={[first, other]} liveEvent={first} uniqueRecentSources />);
    view.rerender(<ThreatMap events={[second, first, other]} liveEvent={second} uniqueRecentSources />);
    act(() => vi.advanceTimersByTime(300));
    view.rerender(<ThreatMap events={[third, second, first, other]} liveEvent={third} uniqueRecentSources />);
    act(() => vi.advanceTimersByTime(300));
    const recent = within(screen.getByRole('region', { name: 'Recent detections' }));
    expect(recent.getAllByRole('button')).toHaveLength(2);
    expect(recent.getAllByText(/103\.1\.2\.3 →/)).toHaveLength(1);
    expect(recent.getByText(/#three · \/latest/)).toBeInTheDocument();
    expect(recent.getByText('3 detections in recent events · latest shown')).toBeInTheDocument();
    const arcs = screen.getAllByTestId('threat-arc');
    expect(arcs).toHaveLength(3);
    expect(arcs.map((arc) => arc.parentElement!.getAttribute('data-event-id'))).toEqual(['one', 'two', 'three']);
    expect(arcs.map((arc) => arc.parentElement!.getAttribute('data-lane'))).toEqual(['0', '1', '-1']);
    fireEvent.click(recent.getByText(/#three · \/latest/));
    expect(screen.getByRole('region', { name: 'Detection details' })).toHaveTextContent('GET /latest');
  });

  it('queues overflow and retains interrupted and newly arriving detections while paused', () => {
    const first = event('one', 23.81, 90.41);
    const view = render(<ThreatMap events={[first]} liveEvent={first} />);
    for (let index = 2; index <= 13; index += 1) {
      const next = event(String(index), 23.81 + index, 90.41);
      view.rerender(<ThreatMap events={[next, first]} liveEvent={next} />);
    }
    act(() => vi.advanceTimersByTime(3300));
    expect(screen.getAllByTestId('threat-arc')).toHaveLength(12);
    expect(screen.getByText('12 animating · 1 queued')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Pause map animations' }));
    expect(screen.queryByTestId('threat-arc')).not.toBeInTheDocument();
    expect(screen.getByText('0 animating · 13 queued')).toBeInTheDocument();
    view.rerender(<ThreatMap events={[first]} liveEvent={event('eight', 40, 20)} />);
    expect(screen.queryByTestId('threat-arc')).not.toBeInTheDocument();
    expect(screen.getByText('0 animating · 14 queued')).toBeInTheDocument();
    act(() => vi.advanceTimersByTime(10000));
    expect(screen.getByText('0 animating · 14 queued')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Resume map animations' }));
    expect(screen.getByTestId('threat-arc')).toBeInTheDocument();
    expect(screen.getByText('1 animating · 13 queued')).toBeInTheDocument();
  });

  it('honors reduced motion and still allows inspecting historical detections', () => {
    reducedMotion.mockReturnValue(true);
    const suspicious = event('bd', 23.81, 90.41);
    render(<ThreatMap events={[suspicious]} liveEvent={suspicious} />);
    expect(screen.queryByTestId('threat-arc')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Pause map animations' })).toBeDisabled();
    fireEvent.mouseEnter(screen.getByRole('button', { name: 'Inspect scanner from bd' }));
    expect(screen.getByRole('region', { name: 'Detection details' })).toHaveTextContent('GET /admin');
    expect(screen.getByRole('region', { name: 'Detection details' })).toHaveTextContent('404');
    expect(screen.getByText(/arcs are illustrative/)).toBeInTheDocument();
  });

  it('does not invent a destination when server coordinates are unavailable', () => {
    const missing = { ...event('unknown', 23.81, 90.41), dest_lat: null, dest_lng: null };
    render(<ThreatMap events={[missing]} liveEvent={missing} />);
    expect(screen.getByText(/Monitored server location unavailable/)).toBeInTheDocument();
    expect(screen.queryByTestId('threat-arc')).not.toBeInTheDocument();
    expect(screen.queryByText('MONITORED SERVER')).not.toBeInTheDocument();
  });
  it('skips route animation when the source location is unknown', () => {
    const unknown = { ...event('unknown', 23.81, 90.41), lat: null, lng: null };
    render(<ThreatMap events={[unknown]} liveEvent={unknown} />);
    expect(screen.getByText('MONITORED SERVER')).toBeInTheDocument();
    expect(screen.queryByTestId('threat-arc')).not.toBeInTheDocument();
    expect(screen.getByText(/unknown → spandan-web/i)).toBeInTheDocument();
  });

  it('uses each event destination and leaves historical backfill quiet', () => {
    const first = event('bd', 23.81, 90.41);
    const second = { ...event('de', 52.52, 13.405), server_id: 'other-web', dest_lat: 48.86, dest_lng: 2.35 };
    const view = render(<ThreatMap events={[first, second]} liveEvent={null} />);
    expect(screen.queryByTestId('threat-arc')).not.toBeInTheDocument();
    view.rerender(<ThreatMap events={[first, second]} liveEvent={first} />);
    view.rerender(<ThreatMap events={[second, first]} liveEvent={second} />);
    act(() => vi.advanceTimersByTime(300));
    expect(screen.getAllByTestId('threat-arc').map((arc) => arc.getAttribute('data-to')))
      .toEqual(['-77.4903,39.0469', '2.35,48.86']);
    expect(screen.getAllByText('MONITORED SERVER')).toHaveLength(2);
  });

  it('shows one quiet historical marker for repeated detections at the same location', () => {
    const first = event('one', 23.81, 90.41);
    const second = event('two', 23.82, 90.42);
    render(<ThreatMap events={[second, first]} liveEvent={null} />);
    expect(screen.getAllByRole('button', { name: /Inspect scanner from/ })).toHaveLength(1);
    expect(screen.getByText('×2')).toBeInTheDocument();
    expect(screen.queryByTestId('threat-arc')).not.toBeInTheDocument();
  });

  it('expires finite route animations instead of leaving persistent rings', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-09-29T00:00:00Z'));
    const suspicious = event('bd', 23.81, 90.41);
    const view = render(<ThreatMap events={[suspicious]} liveEvent={suspicious} />);
    try {
      expect(screen.getByTestId('threat-arc')).toBeInTheDocument();
      act(() => vi.advanceTimersByTime(4500));
      expect(screen.queryByTestId('threat-arc')).not.toBeInTheDocument();
    } finally {
      view.unmount();
      vi.useRealTimers();
    }
  });

  it('opens request details from a keyboard-focusable marker', () => {
    const suspicious = event('bd', 23.81, 90.41);
    render(<ThreatMap events={[suspicious]} liveEvent={null} />);
    const marker = screen.getByRole('button', { name: 'Inspect scanner from bd' });
    act(() => marker.focus());
    fireEvent.keyDown(marker, { key: 'Enter' });
    expect(screen.getByRole('region', { name: 'Detection details' })).toHaveTextContent('GET /admin');
    fireEvent.click(screen.getByRole('button', { name: 'Close detection details' }));
    expect(screen.queryByRole('region', { name: 'Detection details' })).not.toBeInTheDocument();
  });

  it('animates every event in a batched repeated-IP burst, without replaying duplicate IDs', () => {
    let deliver: ((event: ThreatEvent) => void) | undefined;
    const subscribe = (listener: (event: ThreatEvent) => void) => {
      deliver = listener;
      return () => { deliver = undefined; };
    };
    const burst = Array.from({ length: 25 }, (_, index) => ({
      ...event(String(index), 23.81, 90.41), source_ip: '103.1.2.3',
    }));
    render(<ThreatMap events={burst} liveEvent={null} subscribeToDetections={subscribe} />);
    act(() => { for (const detection of burst) deliver?.(detection); deliver?.(burst[0]); });
    const animated = new Set<string>();
    for (let step = 0; step < 100; step += 1) {
      for (const arc of screen.queryAllByTestId('threat-arc')) {
        animated.add(arc.parentElement!.getAttribute('data-event-id')!);
      }
      act(() => vi.advanceTimersByTime(300));
    }
    expect([...animated].sort()).toEqual(burst.map((item) => item.id).sort());
    expect(screen.getByText('0 animating · 0 queued')).toBeInTheDocument();
    expect(screen.getByText('×25')).toBeInTheDocument();
    expect(screen.getAllByText(/103\.1\.2\.3 →/)).toHaveLength(25);
  });

});
