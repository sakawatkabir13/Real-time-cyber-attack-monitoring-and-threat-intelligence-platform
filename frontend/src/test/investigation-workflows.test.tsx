import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import IPLookup from '@/pages/IPLookup';
import LogAnalyzerPage from '@/pages/LogAnalyzerPage';
import EventInspector from '@/components/EventInspector';
import ThreatTable from '@/components/ThreatTable';
import type { ThreatEvent } from '@/hooks/useThreatFeed';

afterEach(() => { cleanup(); vi.restoreAllMocks(); sessionStorage.clear(); });
const event: ThreatEvent = { id: '9', source_ip: '203.0.113.9', server_id: 'spandan-web', attack_type: 'scanner', severity: 'medium', method: 'GET', path: '/private', status_code: 404, dest_port: null, country: 'BD', lat: null, lng: null, timestamp: '2026-10-05T10:00:00Z', explanation: 'Broad directory probing', anomaly_score: null };
const reply = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });

describe('investigation workflows', () => {
  it('opens actual request evidence from the detection table', () => {
    render(<EventInspector><ThreatTable events={[event]} /></EventInspector>);
    fireEvent.click(screen.getByRole('button', { name: 'Inspect event 9 from 203.0.113.9' }));
    expect(screen.getByRole('dialog')).toHaveTextContent('Broad directory probing');
    expect(screen.getByRole('dialog')).toHaveTextContent('GET /private');
    expect(screen.getByRole('dialog')).toHaveTextContent('Not an ML finding');
  });

  it('keeps AI analysis bound to the displayed IP and clears old results after a failed lookup', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(reply({ profile: { ip: event.source_ip, total_attacks: 3, score: 50 }, threats: [], abuseData: { available: false, reason: 'Not configured' } }))
      .mockResolvedValueOnce(reply({ analysis: 'Local evidence only' }))
      .mockResolvedValueOnce(reply({ detail: 'Invalid IP address' }, 422));
    render(<IPLookup />);
    const input = screen.getByRole('textbox', { name: 'IP address to look up' });
    fireEvent.change(input, { target: { value: event.source_ip } });
    fireEvent.click(screen.getByRole('button', { name: 'SCAN' }));
    await screen.findByText(/Results for 203.0.113.9/);
    expect(screen.getByText('UNAVAILABLE')).toBeInTheDocument();
    expect(screen.getAllByText('Unknown')).toHaveLength(2);
    fireEvent.change(input, { target: { value: 'invalid' } });
    fireEvent.click(screen.getByRole('button', { name: 'RUN ANALYSIS' }));
    await screen.findByText('Local evidence only');
    expect(fetchMock.mock.calls[1][1]).toMatchObject({ body: JSON.stringify({ ip: event.source_ip }) });
    fireEvent.click(screen.getByRole('button', { name: 'SCAN' }));
    await screen.findByRole('alert');
    expect(screen.queryByText(/Results for 203.0.113.9/)).not.toBeInTheDocument();
    expect(screen.queryByText('Local detection events')).not.toBeInTheDocument();
  });

  it('tracks the returned upload job instead of the latest global job', async () => {
    const id = 'a'.repeat(32);
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(reply({ jobId: id, lines: 8 }))
      .mockResolvedValueOnce(reply({ jobId: id, state: 'complete', processed: 8, total: 8, rejected: 2, detections: 1 }));
    render(<LogAnalyzerPage />);
    fireEvent.change(screen.getByLabelText('Access log file'), { target: { files: [new File(['log'], 'access.log')] } });
    fireEvent.click(screen.getByRole('button', { name: 'Analyze logs' }));
    await screen.findByText('Analysis complete');
    expect(fetchMock.mock.calls[1][0]).toBe('/api/analysis-status?job_id=' + id);
    expect(screen.getByRole('status')).toHaveTextContent('6 accepted · 2 rejected · 1 rule detections');
    expect(screen.queryByText(/simulation/)).not.toBeInTheDocument();
  });

  it('rejects a wrong job status rather than showing another upload as completed', async () => {
    sessionStorage.setItem('vanguard-analysis-job', 'a'.repeat(32));
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(reply({ jobId: 'b'.repeat(32), state: 'complete', processed: 1, total: 1, rejected: 0 }));
    render(<LogAnalyzerPage />);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('does not match this upload'));
    expect(screen.queryByText('Analysis complete')).not.toBeInTheDocument();
  });

  it('does not resume tracking the previous completed job when a new upload fails', async () => {
    const id = 'a'.repeat(32);
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(reply({ jobId: id, lines: 1 }))
      .mockResolvedValueOnce(reply({ jobId: id, state: 'complete', processed: 1, total: 1, rejected: 0 }))
      .mockResolvedValueOnce(reply({ detail: 'Worker unavailable' }, 503));
    render(<LogAnalyzerPage />);
    fireEvent.change(screen.getByLabelText('Access log file'), { target: { files: [new File(['log'], 'access.log')] } });
    fireEvent.click(screen.getByRole('button', { name: 'Analyze logs' }));
    await screen.findByText('Analysis complete');
    fireEvent.click(screen.getByRole('button', { name: 'Analyze logs' }));
    await screen.findByText('Worker unavailable');
    expect(sessionStorage.getItem('vanguard-analysis-job')).toBeNull();
    expect(screen.queryByText('Analysis complete')).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });
});
