import { fireEvent, render, screen, waitFor, cleanup } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import AlertReviewForm from '@/components/AlertReviewForm';
import RelatedIncidents from '@/components/RelatedIncidents';
import { useAppStore, type Alert } from '@/store/appStore';

const alert: Alert = {
  id: 'alert-1', serverId: 'web-a', sourceIp: '203.0.113.7', targetIp: 'web-a',
  type: 'http_flood', severity: 'High', status: 'new', timestamp: '2026-09-10T10:00:00Z',
  lastSeen: '2026-09-10T10:00:00Z', occurrenceCount: 1, acknowledged: false,
  verdict: 'unreviewed', reviewVersion: 0,
};

function Review() {
  const current = useAppStore((state) => state.alerts[0]);
  return <AlertReviewForm alert={current} />;
}

describe('Alert investigations', () => {
  beforeEach(() => useAppStore.setState({ alerts: [{ ...alert }] }));
  afterEach(() => { cleanup(); vi.restoreAllMocks(); });

  it('saves evidence and a verdict without acknowledging the alert', async () => {
    const saved = { ...alert, verdict: 'legitimate', reviewNotes: 'Reviewed deployment traffic', reviewVersion: 1 };
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(saved)));
    render(<Review />);
    fireEvent.click(screen.getByRole('button', { name: 'Investigate' }));
    fireEvent.change(screen.getByLabelText('Investigation result'), { target: { value: 'legitimate' } });
    fireEvent.change(screen.getByLabelText('Evidence / investigation notes'), { target: { value: 'Reviewed deployment traffic' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save investigation' }));
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Investigation saved'));
    expect(fetchMock).toHaveBeenCalledWith('/api/alerts/alert-1/review', expect.objectContaining({
      method: 'PATCH', body: JSON.stringify({ verdict: 'legitimate', notes: 'Reviewed deployment traffic', expected_version: 0 }),
    }));
    expect(useAppStore.getState().alerts[0].acknowledged).toBe(false);
    expect(screen.getByText('Investigation: Legitimate activity')).toBeInTheDocument();
  });

  it('keeps draft notes on a stale-review conflict', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{}', { status: 409 }));
    render(<Review />);
    fireEvent.click(screen.getByRole('button', { name: 'Investigate' }));
    fireEvent.change(screen.getByLabelText('Evidence / investigation notes'), { target: { value: 'My investigation draft' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save investigation' }));
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Another review was saved'));
    expect(screen.getByLabelText('Evidence / investigation notes')).toHaveValue('My investigation draft');
    expect(useAppStore.getState().alerts[0].verdict).toBe('unreviewed');
  });

  it('requires notes and displays review history separately', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify([
      { version: 1, verdict: 'uncertain', notes: 'Need origin logs', reviewedAt: alert.timestamp, reviewedBy: 'dashboard_operator' },
    ])));
    render(<Review />);
    fireEvent.click(screen.getByRole('button', { name: 'Investigate' }));
    expect(screen.getByRole('button', { name: 'Save investigation' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Review history' }));
    expect(await screen.findByText('Need origin logs')).toBeInTheDocument();
  });

  it('presents groups as related evidence, not shared attacker attribution', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify([
      { id: 'group-1', serverId: 'web-a', type: 'brute_force', path: '/login', sourceCount: 3,
        alertCount: 3, explanation: 'Nearby timing and similar behavior.', lastSeen: alert.timestamp },
    ])));
    render(<RelatedIncidents />);
    expect(await screen.findByText(/3 sources \/ 3 alerts/)).toBeInTheDocument();
    expect(screen.getByText(/does not establish a common attacker/)).toBeInTheDocument();
  });
});
