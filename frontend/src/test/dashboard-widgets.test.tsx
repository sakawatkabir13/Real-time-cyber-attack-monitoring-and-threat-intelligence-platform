import { render, screen, cleanup } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import AlertQueue from '@/components/AlertQueue';
import AnomalyChart from '@/components/AnomalyChart';
import LiveEventFeed from '@/components/LiveEventFeed';
import ThreatTable from '@/components/ThreatTable';
import { mergeThreatEvents, isMlAnomaly, type ThreatEvent } from '@/hooks/useThreatFeed';
import { useAppStore, type Alert } from '@/store/appStore';

const event: ThreatEvent = {
  id: 'event-1',
  server_id: 'spandan-web',
  source_ip: '203.0.113.7',
  dest_port: null,
  method: 'GET',
  path: '/admin',
  status_code: 404,
  attack_type: 'scanner',
  severity: 'medium',
  country: 'BD',
  lat: null,
  lng: null,
  timestamp: '2026-09-29T10:00:00Z',
  anomaly_score: null,
};

const alert: Alert = {
  id: 'alert-1', serverId: 'spandan-web', sourceIp: '203.0.113.7',
  targetIp: null, type: 'sql_injection', severity: 'High',
  status: 'new', timestamp: event.timestamp, lastSeen: event.timestamp,
  occurrenceCount: 1, acknowledged: false, verdict: 'unreviewed', reviewVersion: 0,
};

afterEach(cleanup);

describe('dashboard widget data', () => {
  it('shows a server identity rather than an invented target IP', () => {
    useAppStore.setState((state) => ({
      alerts: [alert], alertsLoading: false,
      settings: { ...state.settings, alertSensitivity: 'high' },
    }));
    render(<AlertQueue />);
    expect(screen.getByText(/Server: spandan-web/)).toBeInTheDocument();
    expect(screen.queryByText(/→/)).not.toBeInTheDocument();
  });

  it('explains when alerts are hidden by sensitivity', () => {
    useAppStore.setState((state) => ({
      alerts: [{ ...alert, severity: 'Medium' }],
      alertsLoading: false,
      settings: { ...state.settings, alertSensitivity: 'high' },
    }));
    render(<AlertQueue />);
    expect(screen.getByText('No new alerts at this sensitivity')).toBeInTheDocument();
  });

  it('shows HTTP context without a fictitious port or null-score crash', () => {
    render(<LiveEventFeed events={[event]} />);
    expect(screen.getByText(/GET \/admin · HTTP 404/)).toBeInTheDocument();
    cleanup();
    render(<ThreatTable events={[event]} />);
    expect(screen.getByText('GET /admin')).toBeInTheDocument();
    expect(screen.getByText('404')).toBeInTheDocument();
    expect(screen.queryByText('PORT')).not.toBeInTheDocument();
  });

  it('keeps rule scores out of the ML anomaly view', () => {
    expect(isMlAnomaly({ ...event, anomaly_score: 75 })).toBe(false);
    expect(isMlAnomaly({ ...event, attack_type: 'server_traffic_anomaly' })).toBe(true);
    render(<AnomalyChart data={[]} />);
    expect(screen.getByText(/No ML anomaly findings yet/)).toBeInTheDocument();
  });

  it('merges reconnect snapshots with live events without duplicates or stale overwrite', () => {
    const live = { ...event, id: 'event-2', timestamp: '2026-09-29T11:00:00Z' };
    const refreshed = { ...event, path: '/reviewed' };
    const merged = mergeThreatEvents([live, event], [refreshed]);
    expect(merged.map((item) => item.id)).toEqual(['event-2', 'event-1']);
    expect(merged[1].path).toBe('/reviewed');
  });
});
