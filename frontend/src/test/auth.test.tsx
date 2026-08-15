import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import AuthGate from '@/components/AuthGate';

describe('AuthGate', () => {
  afterEach(() => vi.restoreAllMocks());

  it('requires a password and reveals the dashboard after successful login', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({ authenticated: false })))
      .mockResolvedValueOnce(new Response(JSON.stringify({ authenticated: true })));

    render(<AuthGate><div>protected dashboard</div></AuthGate>);
    const input = await screen.findByLabelText('PASSWORD');
    fireEvent.change(input, { target: { value: 'correct horse battery staple' } });
    fireEvent.click(screen.getByRole('button', { name: 'SIGN IN' }));

    await waitFor(() => expect(screen.getByText('protected dashboard')).toBeInTheDocument());
    expect(fetchMock).toHaveBeenLastCalledWith('/api/auth/login', expect.objectContaining({ method: 'POST' }));
  });
});
