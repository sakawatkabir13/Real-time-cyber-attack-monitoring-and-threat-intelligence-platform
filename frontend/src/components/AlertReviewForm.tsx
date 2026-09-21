import { useState } from 'react';
import { useAppStore, type Alert, type ReviewVerdict } from '@/store/appStore';

const verdictLabels: Record<ReviewVerdict | 'unreviewed', string> = {
  unreviewed: 'Not investigated', confirmed_malicious: 'Confirmed malicious',
  legitimate: 'Legitimate activity', misconfiguration: 'Technical misconfiguration',
  uncertain: 'Still uncertain',
};

interface ReviewRecord {
  version: number; verdict: ReviewVerdict; notes: string; reviewedAt: string; reviewedBy: string;
}

export default function AlertReviewForm({ alert }: { alert: Alert }) {
  const reviewAlert = useAppStore((state) => state.reviewAlert);
  const loadAlerts = useAppStore((state) => state.loadAlerts);
  const [open, setOpen] = useState(false);
  const [verdict, setVerdict] = useState<ReviewVerdict>(alert.verdict === 'unreviewed' ? 'uncertain' : alert.verdict);
  const [notes, setNotes] = useState(alert.reviewNotes ?? '');
  const [version, setVersion] = useState(alert.reviewVersion);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');
  const [history, setHistory] = useState<ReviewRecord[] | null>(null);

  const reload = async () => {
    await loadAlerts();
    const current = useAppStore.getState().alerts.find((item) => item.id === alert.id);
    if (current) {
      setVerdict(current.verdict === 'unreviewed' ? 'uncertain' : current.verdict);
      setNotes(current.reviewNotes ?? '');
      setVersion(current.reviewVersion);
      setMessage('Loaded the current saved verdict.');
    }
  };

  const loadHistory = async () => {
    try {
      const response = await fetch(`/api/alerts/${encodeURIComponent(alert.id)}/reviews`);
      if (!response.ok) throw new Error();
      setHistory(await response.json() as ReviewRecord[]);
    } catch {
      setMessage('Review history could not be loaded.');
    }
  };

  return (
    <div className="mt-3 text-xs space-y-2">
      <div className="flex flex-wrap items-center gap-3">
        <span>Investigation: {verdictLabels[alert.verdict]}</span>
        <button type="button" onClick={() => setOpen(!open)} className="underline text-primary">
          {open ? 'Close investigation' : 'Investigate'}
        </button>
        <button type="button" onClick={() => void loadHistory()} className="underline">Review history</button>
      </div>
      {alert.reviewNotes && !open && <p className="whitespace-pre-wrap break-words">{alert.reviewNotes}</p>}
      {open && (
        <form className="space-y-2 border border-border rounded p-3" onSubmit={async (event) => {
          event.preventDefault();
          if (!notes.trim() || saving) return;
          setSaving(true);
          const error = await reviewAlert(alert.id, verdict, notes.trim(), version);
          setSaving(false);
          setMessage(error ?? 'Investigation saved. Acknowledgment and ML training are unchanged.');
          if (!error) { setVersion(version + 1); setHistory(null); }
        }}>
          <p className="text-muted-foreground">Record investigation evidence. ACK only means someone has seen the alert.</p>
          <label className="block" htmlFor={`verdict-${alert.id}`}>Investigation result</label>
          <select id={`verdict-${alert.id}`} value={verdict} disabled={saving}
            onChange={(event) => setVerdict(event.target.value as ReviewVerdict)}
            className="w-full bg-background border border-border rounded p-2">
            {Object.entries(verdictLabels).filter(([value]) => value !== 'unreviewed').map(([value, label]) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>
          <label className="block" htmlFor={`notes-${alert.id}`}>Evidence / investigation notes</label>
          <textarea id={`notes-${alert.id}`} required maxLength={4000} rows={3} value={notes} disabled={saving}
            onChange={(event) => setNotes(event.target.value)} className="w-full bg-background border border-border rounded p-2" />
          <div className="flex flex-wrap gap-3">
            <button type="submit" disabled={saving || !notes.trim()} className="border border-border rounded px-3 py-2 disabled:opacity-50">
              {saving ? 'Saving…' : 'Save investigation'}
            </button>
            <button type="button" disabled={saving} onClick={() => void reload()} className="underline">Reload saved verdict (replace draft)</button>
          </div>
        </form>
      )}
      {message && <p role="status">{message}</p>}
      {history && (
        <div className="space-y-2 border-l border-border pl-3">
          {history.length === 0 && <p>No investigation history yet.</p>}
          {history.map((review) => (
            <div key={review.version}>
              <p>#{review.version} · {verdictLabels[review.verdict]} · {new Date(review.reviewedAt).toLocaleString()}</p>
              <p className="whitespace-pre-wrap break-words">{review.notes}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
