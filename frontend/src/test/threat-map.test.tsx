import type { ReactNode } from 'react';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import ThreatMap from '@/components/ThreatMap';
import type { ThreatEvent } from '@/hooks/useThreatFeed';

vi.mock('react-simple-maps', () => ({
  ComposableMap: ({ children }: { children: ReactNode }) => <svg>{children}</svg>,
  ZoomableGroup: ({ children }: { children: ReactNode }) => <g>{children}</g>,
  Geographies: ({ children }: { children: (value: { geographies: [] }) => ReactNode }) =>
    <g>{children({ geographies: [] })}</g>,
  Geography: () => <g />,
  Marker: ({ coordinates, children }: { coordinates: number[]; children: ReactNode }) =>
    <g data-coordinates={coordinates.join(',')}>{children}</g>,
  Line: ({ from, to }: { from: number[]; to: number[] }) =>
    <path data-testid="threat-arc" data-from={from.join(',')} data-to={to.join(',')} />,
}));

vi.mock('framer-motion', () => ({
  AnimatePresence: ({ children }: { children: ReactNode }) => <>{children}</>,
  motion: { circle: () => <circle /> },
}));

function event(id: string, lat: number, lng: number): ThreatEvent {
  return {
    id,
    server_id: 'spandan-web',
    source_ip: id,
    dest_port: null,
    attack_type: 'scanner',
    severity: 'medium',
    country: 'Unknown',
    lat,
    lng,
    dest_lat: 39.0469,
    dest_lng: -77.4903,
    timestamp: '2026-09-29T00:00:00Z',
  };
}

describe('ThreatMap', () => {
  it('routes independent sources to the same monitored server marker', () => {
    const bangladesh = event('bd', 23.81, 90.41);
    const germany = event('de', 52.52, 13.405);
    const view = render(<ThreatMap events={[bangladesh, germany]} liveEvent={bangladesh} />);
    view.rerender(<ThreatMap events={[germany, bangladesh]} liveEvent={germany} />);

    expect(screen.getByText('MONITORED SERVER').parentElement)
      .toHaveAttribute('data-coordinates', '-77.4903,39.0469');
    const arcs = screen.getAllByTestId('threat-arc');
    expect(arcs).toHaveLength(2);
    expect(arcs.map((arc) => arc.getAttribute('data-from')))
      .toEqual(['13.405,52.52', '90.41,23.81']);
    expect(arcs.map((arc) => arc.getAttribute('data-to')))
      .toEqual(['-77.4903,39.0469', '-77.4903,39.0469']);
  });
});
