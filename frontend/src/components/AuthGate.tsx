import { FormEvent, useEffect, useState } from 'react';
import { Loader2, Shield } from 'lucide-react';

export default function AuthGate({ children }: { children: React.ReactNode }) {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null);
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    fetch('/api/auth/status')
      .then((response) => response.json())
      .then((data) => setAuthenticated(Boolean(data.authenticated)))
      .catch(() => setAuthenticated(false));
  }, []);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    setError('');
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.detail || 'Login failed');
      }
      setAuthenticated(true);
      setPassword('');
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Login failed');
    } finally {
      setSubmitting(false);
    }
  };

  if (authenticated === null) {
    return <div className="h-screen grid place-items-center bg-background"><Loader2 className="animate-spin text-primary" /></div>;
  }
  if (authenticated) return <>{children}</>;

  return (
    <main className="h-screen grid place-items-center bg-background cyber-grid p-6">
      <form onSubmit={submit} className="w-full max-w-sm rounded-lg border border-border bg-card p-8 space-y-5">
        <div className="flex items-center gap-3">
          <Shield className="h-9 w-9 text-primary" />
          <div>
            <h1 className="font-display font-bold text-primary">VANGUARD-360</h1>
            <p className="text-xs font-mono text-muted-foreground">Dashboard authentication</p>
          </div>
        </div>
        <label className="block text-xs font-mono text-muted-foreground">
          PASSWORD
          <input
            autoFocus
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            className="mt-2 w-full rounded-md border border-border bg-background px-3 py-2 text-foreground outline-none focus:ring-1 focus:ring-primary"
          />
        </label>
        {error && <p role="alert" className="text-xs text-destructive">{error}</p>}
        <button disabled={submitting || !password} className="w-full rounded-md bg-primary px-4 py-2 text-sm font-mono text-primary-foreground disabled:opacity-50">
          {submitting ? 'AUTHENTICATING…' : 'SIGN IN'}
        </button>
      </form>
    </main>
  );
}
