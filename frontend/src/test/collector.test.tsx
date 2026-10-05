import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import CollectorControl from '@/components/CollectorControl';


const runningCollector = {
  serverId: 'web-01',
  desiredState: 'running',
  reportedState: 'running',
  commandVersion: 0,
  spoolDepth: 4,
  agentVersion: '2.0.0',
  lastError: null,
  lastSeen: '2026-08-05T00:00:00Z',
};


describe('CollectorControl', () => {
  afterEach(() => vi.restoreAllMocks());

  it('loads backend state and persists a pause command', async () => {
    const pausedCollector = {
      ...runningCollector,
      desiredState: 'paused',
      commandVersion: 1,
    };
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify([runningCollector])))
      .mockResolvedValueOnce(new Response(JSON.stringify(pausedCollector)));

    const view = render(<CollectorControl />);
    fireEvent.click(await screen.findByRole('button', { name: 'Pause forwarding' }));
    expect(fetchMock).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: 'Confirm pause' }));

    await waitFor(() => expect(screen.getByRole('button', { name: 'Resume forwarding' })).toBeInTheDocument());
    expect(fetchMock).toHaveBeenLastCalledWith(
      '/api/collectors/web-01/command',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ desired_state: 'paused' }),
      }),
    );
    view.unmount();
  });
});
