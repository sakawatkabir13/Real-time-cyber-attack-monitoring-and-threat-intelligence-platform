import { useEffect, useRef, useState } from 'react';
import { UploadCloud } from 'lucide-react';

const MAX_SIZE = 50 * 1024 * 1024;
interface AnalysisJob {
  jobId: string; state: string; processed: number; total: number; rejected: number;
  detections?: number; error?: string | null;
}
export default function LogAnalyzerPage() {
  const [file, setFile] = useState<File | null>(null);
  const [jobId, setJobId] = useState(() => sessionStorage.getItem('vanguard-analysis-job') || '');
  const [job, setJob] = useState<AnalysisJob | null>(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState('');
  const [pollError, setPollError] = useState('');
  const fileInput = useRef<HTMLInputElement>(null);
  const polling = Boolean(jobId) && !['complete', 'error'].includes(job?.state || '');
  const busy = uploading || polling;
  useEffect(() => {
    if (!polling) return;
    let cancelled = false;
    let inFlight = false;
    const poll = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const response = await fetch('/api/analysis-status?job_id=' + encodeURIComponent(jobId));
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Could not read job status');
        if (data.jobId !== jobId) throw new Error('Job status does not match this upload');
        if (!cancelled) { setJob(data as AnalysisJob); setPollError(''); }
      } catch (reason) {
        if (!cancelled) setPollError(reason instanceof Error ? reason.message : 'Status unavailable');
      } finally { inFlight = false; }
    };
    void poll();
    const timer = window.setInterval(() => void poll(), 2000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [jobId, polling]);

  const selectFile = (value?: File) => {
    if (!value || busy) return;
    setError('');
    if (!/\.(log|txt|jsonl)$/i.test(value.name)) { setFile(null); setError('Choose a .log, .txt or .jsonl access-log file.'); return; }
    if (value.size > MAX_SIZE) { setFile(null); setError('File exceeds the 50 MB upload limit. Split it into smaller files.'); return; }
    if (!value.size) { setFile(null); setError('The selected file is empty.'); return; }
    setFile(value);
  };
  const upload = async () => {
    if (!file || busy) return;
    setUploading(true); setError(''); setPollError(''); setJob(null);
    setJobId(''); sessionStorage.removeItem('vanguard-analysis-job');
    const body = new FormData(); body.append('file', file);
    try {
      const response = await fetch('/api/analyze-log-file', { method: 'POST', body });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || 'Upload failed (' + response.status + ')');
      if (!data.jobId) throw new Error('The server did not return an analysis job ID');
      sessionStorage.setItem('vanguard-analysis-job', data.jobId);
      setJobId(data.jobId);
      setJob({ jobId: data.jobId, state: 'queued', processed: 0, rejected: 0, total: data.lines });
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Upload failed'); }
    finally { setUploading(false); }
  };
  return <div className="p-4 sm:p-6 space-y-6 max-w-5xl">
    <div><h1 className="text-2xl font-bold">Log Analyzer</h1><p className="mt-2 text-sm text-muted-foreground">Upload Nginx or Apache access logs, or JSON lines. Detection uses original request times; completed windows are scored separately when a compatible ML model is available.</p></div>
    <div className="rounded border border-border bg-card p-4 text-sm">
      <p>Accepted files: .log, .txt, .jsonl · Maximum 50 MB</p>
      <p className="mt-2 text-muted-foreground">Use valid IP addresses and timestamps with a timezone. JSON logs can include method, path, status, bytes, request duration and user agent.</p>
    </div>
    <section aria-label="Upload access logs" onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); selectFile(event.dataTransfer.files[0]); }} className="rounded-lg border-2 border-dashed border-border bg-card/60 p-6 sm:p-10 text-center">
      <UploadCloud className="mx-auto mb-4 h-12 w-12 text-primary" />
      <p className="break-all font-semibold">{file ? file.name : 'Drop your access log here'}</p>
      {file && <p className="mt-2 text-sm text-muted-foreground">{(file.size / 1024 / 1024).toFixed(2)} MB</p>}
      <input ref={fileInput} type="file" accept=".log,.txt,.jsonl" aria-label="Access log file" className="sr-only" disabled={busy} onChange={(event) => selectFile(event.target.files?.[0])} />
      <div className="mt-4 flex flex-wrap justify-center gap-3">
        <button disabled={busy} onClick={() => fileInput.current?.click()} className="rounded border border-border px-4 py-3 disabled:opacity-50">{file ? 'Choose another file' : 'Select file'}</button>
        <button disabled={!file || busy} onClick={() => void upload()} className="rounded bg-primary px-4 py-3 text-primary-foreground disabled:opacity-50">{uploading ? 'Uploading…' : polling ? 'Analysis running' : 'Analyze logs'}</button>
      </div>
    </section>
    {error && <p role="alert" className="rounded border border-destructive/40 bg-destructive/10 p-4 text-destructive">{error}</p>}
    {pollError && <div role="alert" className="rounded border border-warning/40 p-4 text-warning"><p>{pollError}. Status checking will retry; the worker may still be processing.</p><button onClick={() => { setJobId(''); setJob(null); sessionStorage.removeItem('vanguard-analysis-job'); }} className="mt-2 min-h-10 underline">Dismiss local job tracking</button></div>}
    {job && <section aria-label="Analysis progress" className="rounded border border-border bg-card p-4 space-y-3">
      <h2 className="font-semibold">{job.state === 'complete' ? 'Analysis complete' : job.state === 'error' ? 'Analysis failed' : job.state === 'queued' ? 'Waiting for worker' : 'Analysis in progress'}</h2>
      <p className="break-all text-xs text-muted-foreground">Job {job.jobId} · status retained for 7 days</p>
      <progress className="w-full" aria-label="Lines processed" value={job.processed} max={job.total || 1} />
      <p role="status" className="text-sm">{job.processed} / {job.total} lines checked · {Math.max(0, job.processed - job.rejected)} accepted · {job.rejected} rejected · {job.detections ?? 0} rule detections</p>
      {job.rejected > 0 && <p className="text-sm text-warning">Rejected lines could not be parsed. Check timestamp timezone, IP addresses, required log fields and numeric measurements.</p>}
      {job.error && <p role="alert" className="break-words text-destructive">{job.error}</p>}
      {job.state === 'complete' && <p className="text-sm">Stored findings are available in the <a href="/" className="text-primary underline">Dashboard</a>. Choose a period that includes the log dates. Later ML findings are separate from this rule-detection count.</p>}
    </section>}
  </div>;
}
