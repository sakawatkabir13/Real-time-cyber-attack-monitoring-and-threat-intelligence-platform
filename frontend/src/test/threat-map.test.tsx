import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { geoEqualEarth, geoPath } from 'd3-geo';
import ThreatMap from '@/components/ThreatMap';
import { routeCoordinates } from '@/components/mapGeometry';
import type { ThreatEvent } from '@/hooks/useThreatFeed';

const reducedMotion = vi.hoisted(() => vi.fn(() => false));
const projection = geoEqualEarth().scale(190).translate([700, 310]);

vi.mock('react-simple-maps', () => ({
  ComposableMap: ({ children, projection, projectionConfig, width, height }: {
    children: ReactNode; projection: string; projectionConfig: { scale: number }; width: number; height: number;
  }) => <svg data-testid="map-projection" data-projection={projection} data-scale={projectionConfig.scale}
    data-width={width} data-height={height}>{children}</svg>,
  ZoomableGroup: ({ children }: { children: ReactNode }) => <g>{children}</g>,
  useMapContext: () => ({ width: 1400, height: 620, projection }),
  useZoomPanContext: () => ({ k: 1 }),
  Geographies: ({ children }: { children: (value: { geographies: [] }) => ReactNode }) =>
    <g>{children({ geographies: [] })}</g>,
  Geography: () => <g />,
  Marker: ({ coordinates, children }: { coordinates: number[]; children: ReactNode }) =>
    <g data-coordinates={coordinates.join(',')}>{children}</g>,
}));
vi.mock('framer-motion', () => ({ useReducedMotion: reducedMotion }));

class CanvasPath {
  points: number[][] = [];
  moveTo(x: number, y: number) { this.points.push([x, y]); }
  lineTo(x: number, y: number) { this.points.push([x, y]); }
}
let strokes: { path: CanvasPath; color: string }[] = [];
const context = {
  strokeStyle: '', globalAlpha: 1, lineWidth: 1, lineDashOffset: 0,
  lineCap: 'round', lineJoin: 'round',
  setTransform: vi.fn(), setLineDash: vi.fn(), beginPath: vi.fn(), arc: vi.fn(),
  clearRect: () => { strokes = []; },
  stroke: (path?: CanvasPath) => {
    if (path && context.globalAlpha > 0) strokes.push({ path, color: context.strokeStyle });
  },
};
const paths = () => [...new Map(strokes.map((stroke) => [stroke.path, stroke])).values()];
const frame = () => act(() => vi.advanceTimersByTime(20));

function event(id: string, lat = 23.81, lng = 90.41): ThreatEvent {
  return {
    id, server_id: 'spandan-web', source_ip: id, dest_port: null, method: 'GET',
    path: '/admin', status_code: 404, attack_type: 'scanner', severity: 'medium',
    country: 'BD', lat, lng, dest_lat: 39.0469, dest_lng: -77.4903, timestamp: '2026-09-29T00:00:00Z',
  };
}
beforeEach(() => {
  reducedMotion.mockReturnValue(false);
  vi.useFakeTimers();
  vi.stubGlobal('Path2D', CanvasPath);
  vi.stubGlobal('ResizeObserver', class { observe() {} disconnect() {} });
  vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(context as unknown as CanvasRenderingContext2D);
  strokes = [];
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers(); });

describe('shared immediate traffic map', () => {
  it('draws normal requests neutrally without adding source dots, cards or detection counts', () => {
    const normal = { ...event('normal'), kind: 'http_request' as const, attack_type: 'http_request', severity: 'normal' };
    const view = render(<ThreatMap events={[]} trafficEvents={[normal]} liveEvent={normal} />);
    frame();
    expect(paths().map((stroke) => stroke.color)).toEqual(['#94a3b8']);
    expect(screen.queryByRole('button', { name: /Inspect .* from normal/ })).not.toBeInTheDocument();
    expect(screen.getByText(/RECENT DETECTIONS · 0 SOURCES/)).toBeInTheDocument();
    expect(screen.getByText('No detections recorded yet')).toBeInTheDocument();
    const scanner = event('scanner', 52.52, 13.405);
    view.rerender(<ThreatMap events={[scanner]} trafficEvents={[normal, scanner]} liveEvent={scanner} />);
    frame();
    expect(paths().map((stroke) => stroke.color)).toEqual(['#94a3b8', '#fbbf24']);
    expect(screen.getAllByRole('button', { name: /Inspect .* from/ })).toHaveLength(1);
  });

  it('starts all 1000 delivered requests in the next frame without a queue or duplicate replay', () => {
    let deliver!: (event: ThreatEvent) => void;
    const unsubscribe = vi.fn();
    const subscribe = (listener: typeof deliver) => { deliver = listener; return unsubscribe; };
    const burst = Array.from({ length: 1000 }, (_, index) => ({
      ...event(String(index), 20 + index % 40, -150 + index % 300),
      timestamp: new Date(index * 1000).toISOString(),
    }));
    const view = render(<ThreatMap events={[]} liveEvent={null} subscribeToTraffic={subscribe} />);
    act(() => { for (const item of burst) deliver(item); deliver(burst[0]); });
    frame();
    expect(paths()).toHaveLength(1000);
    expect(screen.getByText('1000 live arcs · immediate display')).toBeInTheDocument();
    expect(screen.queryByText(/queued|Queued playback/)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Pause map|Resume map/ })).not.toBeInTheDocument();
    act(() => vi.advanceTimersByTime(4500));
    expect(paths()).toHaveLength(0);
    expect(screen.getByText('0 live arcs · immediate display')).toBeInTheDocument();
    act(() => deliver(burst[0]));
    frame();
    expect(paths()).toHaveLength(0);
    view.unmount();
    expect(unsubscribe).toHaveBeenCalledOnce();
  });

  it.each([false, true])('uses the same live renderer with recent-detections panel=%s', (showRecentDetections) => {
    const item = event('same');
    render(<ThreatMap events={[item]} liveEvent={item} showRecentDetections={showRecentDetections} />);
    frame();
    expect(paths()).toHaveLength(1);
    expect(paths()[0].path.points[0]).toEqual(projection([90.41, 23.81]));
    expect(paths()[0].path.points.at(-1)).toEqual(projection([-77.4903, 39.0469]));
    expect(Boolean(screen.queryByRole('region', { name: 'Recent detections' }))).toBe(showRecentDetections);
    expect(screen.getByText('LIVE · NO PLAYBACK QUEUE')).toBeInTheDocument();
  });

  it('routes independent sources only to their monitored destination', () => {
    const bd = event('bd');
    const de = { ...event('de', 52.52, 13.405), server_id: 'other-web', dest_lat: 48.86, dest_lng: 2.35 };
    const view = render(<ThreatMap events={[bd, de]} liveEvent={bd} />);
    view.rerender(<ThreatMap events={[de, bd]} liveEvent={de} />);
    frame();
    expect(paths()).toHaveLength(2);
    expect(paths().map(({ path }) => path.points[0])).toEqual([projection([90.41, 23.81]), projection([13.405, 52.52])]);
    expect(paths().map(({ path }) => path.points.at(-1))).toEqual([projection([-77.4903, 39.0469]), projection([2.35, 48.86])]);
    expect(paths()[0].path.points).toHaveLength(49);
    expect(screen.getAllByText('MONITORED SERVER')).toHaveLength(2);
  });

  it('keeps all repeated requests live while grouping only the source cards', () => {
    const first = { ...event('one'), source_ip: '103.1.2.3', path: '/first' };
    const second = { ...first, id: 'two', path: '/second' };
    const third = { ...first, id: 'three', path: '/latest' };
    const view = render(<ThreatMap events={[first]} liveEvent={first} />);
    view.rerender(<ThreatMap events={[second, first]} liveEvent={second} />);
    view.rerender(<ThreatMap events={[third, second, first]} liveEvent={third} />);
    frame();
    expect(paths()).toHaveLength(3);
    expect(new Set(paths().map(({ path }) => JSON.stringify(path.points[24]))).size).toBe(3);
    const recent = within(screen.getByRole('region', { name: 'Recent detections' }));
    expect(recent.getAllByRole('button')).toHaveLength(1);
    expect(recent.getByText('3 detections in recent events · latest shown')).toBeInTheDocument();
    fireEvent.click(recent.getByText(/#three · \/latest/));
    expect(screen.getByRole('region', { name: 'Detection details' })).toHaveTextContent('GET /latest');
  });

  it('retains severity colors and wakes again after the renderer has become idle', () => {
    let deliver!: (event: ThreatEvent) => void;
    const subscribe = (listener: typeof deliver) => { deliver = listener; return () => {}; };
    render(<ThreatMap events={[]} liveEvent={null} subscribeToTraffic={subscribe} />);
    frame();
    act(() => {
      for (const severity of ['normal', 'low', 'medium', 'high', 'critical']) deliver({ ...event(severity), severity });
    });
    frame();
    expect(paths().map(({ color }) => color)).toEqual(['#94a3b8', '#67e8f9', '#fbbf24', '#fb923c', '#fb4b62']);
    act(() => vi.advanceTimersByTime(10000));
    expect(paths()).toHaveLength(0);
    act(() => deliver(event('after-idle')));
    frame();
    expect(paths()).toHaveLength(1);
    expect(screen.getByText('1 live arcs · immediate display')).toBeInTheDocument();
  });

  it('honors system reduced motion while keeping detection inspection available', () => {
    reducedMotion.mockReturnValue(true);
    const item = event('bd');
    render(<ThreatMap events={[item]} liveEvent={item} />);
    frame();
    expect(paths()).toHaveLength(0);
    expect(screen.getByText('System reduced-motion preference enabled')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Pause map/ })).not.toBeInTheDocument();
    fireEvent.mouseEnter(screen.getByRole('button', { name: 'Inspect scanner from bd' }));
    expect(screen.getByRole('region', { name: 'Detection details' })).toHaveTextContent('GET /admin');
  });

  it('shows the configured server even without any detections', () => {
    render(<ThreatMap events={[]} liveEvent={null} mapTarget={{ serverId: 'spandan-web', lat: 39.0469, lng: -77.4903 }} />);
    expect(screen.getByText('MONITORED SERVER').parentElement).toHaveAttribute('data-coordinates', '-77.4903,39.0469');
    expect(screen.queryByText(/Monitored server location unavailable/)).not.toBeInTheDocument();
  });
  it('uses configured coordinates for legacy requests without a destination', () => {
    const legacy = { ...event('legacy'), dest_lat: null, dest_lng: null };
    render(<ThreatMap events={[legacy]} liveEvent={legacy} mapTarget={{ serverId: 'spandan-web', lat: 39.0469, lng: -77.4903 }} />);
    frame();
    expect(paths()[0].path.points.at(-1)).toEqual(projection([-77.4903, 39.0469]));
  });
  it('shows loading rather than missing location while configuration is loading', () => {
    render(<ThreatMap events={[]} liveEvent={null} mapTargetLoading />);
    expect(screen.getByText(/Loading monitored server location/)).toBeInTheDocument();
    expect(screen.queryByText(/Monitored server location unavailable/)).not.toBeInTheDocument();
  });
  it('does not invent missing source or destination locations', () => {
    const item = { ...event('unknown'), lat: null, lng: null, dest_lat: null, dest_lng: null };
    render(<ThreatMap events={[item]} trafficEvents={[item]} liveEvent={item} />);
    frame();
    expect(paths()).toHaveLength(0);
    expect(screen.getByText(/Monitored server location unavailable/)).toBeInTheDocument();
    expect(screen.getByText(/Some requests cannot be geolocated/)).toBeInTheDocument();
  });
  it('does not animate old snapshots or change detection-only marker counts', () => {
    const first = event('one');
    const second = event('two', 23.82, 90.42);
    render(<ThreatMap events={[second, first]} trafficEvents={[first, second]} liveEvent={null} />);
    frame();
    expect(paths()).toHaveLength(0);
    expect(screen.getAllByRole('button', { name: /Inspect scanner from/ })).toHaveLength(1);
    expect(screen.getByText('×2')).toBeInTheDocument();
  });
  it('renders aggregate ML findings at the server, not an invented attacker location', () => {
    const aggregate = { ...event('aggregate'), source_ip: 'Multiple sources', lat: null, lng: null,
      attack_type: 'server_traffic_anomaly', anomaly_score: 96 };
    render(<ThreatMap events={[aggregate]} liveEvent={aggregate} />);
    frame();
    expect(paths()).toHaveLength(0);
    expect(screen.getByText(/ML AGGREGATE · 96/)).toBeInTheDocument();
  });
  it('opens detection details from the keyboard', () => {
    const item = event('bd');
    render(<ThreatMap events={[item]} liveEvent={null} />);
    fireEvent.keyDown(screen.getByRole('button', { name: 'Inspect scanner from bd' }), { key: 'Enter' });
    expect(screen.getByRole('region', { name: 'Detection details' })).toHaveTextContent('GET /admin');
    fireEvent.click(screen.getByRole('button', { name: 'Close detection details' }));
    expect(screen.queryByRole('region', { name: 'Detection details' })).not.toBeInTheDocument();
  });
});

describe('stable map geometry', () => {
  it('fits the full world inside the map viewport', () => {
    const [[left, top], [right, bottom]] = geoPath(projection).bounds({ type: 'Sphere' });
    expect(left).toBeGreaterThan(0); expect(top).toBeGreaterThan(0);
    expect(right).toBeLessThan(1400); expect(bottom).toBeLessThan(620);
  });
  it('uses a full curved path with unchanged endpoints', () => {
    const points = routeCoordinates([13.405, 52.52], [-77.4903, 39.0469]);
    expect(points).toHaveLength(49);
    expect(points[0]).toEqual([13.405, 52.52]);
    expect(points[48]).toEqual([-77.4903, 39.0469]);
    expect(points[24][1]).toBeGreaterThan((52.52 + 39.0469) / 2);
  });
  it('does not reverse direction at the map seam', () => {
    const points = routeCoordinates([170, 70], [-170, 70]);
    expect(Math.max(...points.slice(1).map((point, index) => Math.abs(point[0] - points[index][0])))).toBeLessThan(10);
    expect(points.every(([lng, lat]) => Math.abs(lng) <= 180 && Math.abs(lat) <= 82)).toBe(true);
  });
  it('separates repeat-source lanes without moving the endpoints', () => {
    const paths = [0, 1, -1].map((lane) => routeCoordinates([0, -30], [0, 30], lane));
    expect(new Set(paths.map((path) => JSON.stringify(path[24]))).size).toBe(3);
    for (const path of paths) { expect(path[0]).toEqual([0, -30]); expect(path[48]).toEqual([0, 30]); }
  });
});
