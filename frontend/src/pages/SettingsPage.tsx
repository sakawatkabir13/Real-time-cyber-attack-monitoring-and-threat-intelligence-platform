import { useAppStore } from '../store/appStore';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card';
import { Switch } from '../components/ui/switch';
import { Label } from '../components/ui/label';
import { BrainCircuit, ShieldAlert } from 'lucide-react';
import { useEffect, useState } from 'react';

interface MlStatus {
  state: 'warming_up' | 'ready';
  version?: string | null;
  featureSchema?: number;
  modelFresh?: boolean | null;
  scorerLastSeen?: string | null;
  grouperLastSeen?: string | null;
  celeryPipelineLastSeen?: string | null;
  collectorLastSeen?: string | null;
  eligibleWindows: Record<string, number>;
  minimumTrainingWindows: number;
  models: Record<string, { samples: number }>;
  eligibleWindowsByServer?: Record<string, Record<string, number>>;
  recentRuns?: Array<{
    scope: string; serverId: string; status: string; samples: number;
    trainedAt?: string | null; error?: string | null;
  }>;
  trainingDays?: number;
  trafficWindowSeconds?: Record<string, number>;
  trainingScheduleUtc?: string;
  trainingDiagnostics?: Record<string, Record<string, { totalWindows: number; tooSparse: number; ruleExcluded: number; scannerExcluded: number; eligible: number; minimumRequests: number }>>;
}

function heartbeatTime(value?: string | null) {
  if (!value) return 'No recent heartbeat';
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 'Invalid heartbeat';
  return new Date(parsed * 1000).toLocaleString();
}

export default function SettingsPage() {
  const { settings, updateSettings } = useAppStore();
  const [mlStatus, setMlStatus] = useState<MlStatus | null>(null);
  const [statusError, setStatusError] = useState('');
  const [updatedAt, setUpdatedAt] = useState('');
  const [refreshVersion, setRefreshVersion] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const refresh = async () => {
      try {
        const response = await fetch('/api/ml/status');
        if (!response.ok) throw new Error(`ML diagnostics unavailable (${response.status})`);
        const data = await response.json() as MlStatus;
        if (!cancelled) { setMlStatus(data); setStatusError(''); setUpdatedAt(new Date().toISOString()); }
      } catch (reason) { if (!cancelled) setStatusError(reason instanceof Error ? reason.message : 'ML status unavailable'); }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 30000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [refreshVersion]);

  return (
    <div className="p-6 h-full flex flex-col space-y-6">
      <div>
        <h1 className="text-2xl font-bold font-display text-foreground">Settings</h1>
        <p className="text-sm font-mono text-muted-foreground">System configuration and preferences</p>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card className="bg-card/50 border-border">
          <CardHeader>
            <CardTitle className="text-lg">General Preferences</CardTitle>
            <CardDescription>Configure basic application settings.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <Label htmlFor="theme-toggle" className="font-mono cursor-pointer">Dark Theme</Label>
              <Switch
                id="theme-toggle"
                checked={settings.theme === 'dark'}
                onCheckedChange={(checked) => updateSettings({ theme: checked ? 'dark' : 'light' })}
              />
            </div>
            <div className="flex items-center justify-between">
              <Label htmlFor="auto-refresh" className="font-mono cursor-pointer">Auto Refresh Feeds</Label>
              <Switch
                id="auto-refresh"
                checked={settings.autoRefresh}
                onCheckedChange={(checked) => updateSettings({ autoRefresh: checked })}
              />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/50 border-border">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-primary" />
              Alert Display
            </CardTitle>
            <CardDescription>Choose which persisted incidents appear in alert views.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="alert-sensitivity" className="font-mono">Minimum displayed severity</Label>
              <select
                id="alert-sensitivity"
                value={settings.alertSensitivity}
                onChange={(event) => updateSettings({ alertSensitivity: event.target.value as typeof settings.alertSensitivity })}
                className="w-full bg-background border border-border rounded-md px-3 py-2 font-mono text-sm"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical Only</option>
              </select>
              <p className="text-xs text-muted-foreground">This filters alert views. It does not change detection rules or model thresholds.</p>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/50 border-border md:col-span-2">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <BrainCircuit className="w-5 h-5 text-primary" />
              Behavioral ML
            </CardTitle>
            <CardDescription>Models learn from real traffic that passes the baseline selection checks. Rules continue detecting while a model collects its baseline.</CardDescription>
            <div className="flex flex-wrap items-center justify-between gap-2 text-sm"><span className="text-muted-foreground">{updatedAt ? `Updated ${new Date(updatedAt).toLocaleTimeString()} · refreshes every 30 seconds` : 'Loading diagnostics…'}</span><button className="rounded border border-border px-3 py-2" onClick={() => setRefreshVersion((value) => value + 1)}>Refresh ML status</button></div>
            {statusError && <p role="alert" className="text-sm text-destructive">{statusError}. Previously displayed data may be stale.</p>}
          </CardHeader>
          <CardContent className="grid gap-3 sm:grid-cols-2 font-mono text-sm">
            <div>Status: <span className="text-primary">{mlStatus?.state === 'warming_up' ? 'Collecting baseline (warming up)' : mlStatus?.state === 'ready' ? 'Model available' : 'Unavailable'}</span></div>
            <div>Version: <span className="text-muted-foreground">{mlStatus?.version ?? 'not trained'}</span></div>
            <div>Feature schema: <span className="text-muted-foreground">{mlStatus?.featureSchema ?? '—'}</span></div>
            <div>Model freshness: <span className="text-muted-foreground">{
              mlStatus?.modelFresh === null || mlStatus?.modelFresh === undefined
                ? 'warming up' : mlStatus.modelFresh ? 'current' : 'stale'
            }</span></div>
            {(['server', 'source'] as const).map((scope) => (
              <div key={scope} className="rounded border border-border p-3">
                <div className="uppercase text-xs text-muted-foreground">{scope} model</div>
                <div className="mt-1">
                  {mlStatus?.eligibleWindows?.[scope] ?? 0} usable baseline windows
                </div>
                {Object.entries(mlStatus?.trainingDiagnostics?.[scope] ?? {}).map(([server, values]) => <div key={server} className="mt-3 space-y-2 border-t border-border pt-3">
                  <p>{server}: {values.eligible} / {mlStatus?.minimumTrainingWindows} required</p>
                  <progress aria-label={`${server} ${scope} baseline progress`} value={Math.min(values.eligible, mlStatus?.minimumTrainingWindows || 200)} max={mlStatus?.minimumTrainingWindows || 200} className="w-full" />
                  <p className="text-xs text-muted-foreground">Last {mlStatus?.trainingDays ?? 30} days: {values.totalWindows} windows · {values.tooSparse} below {values.minimumRequests} requests · {values.ruleExcluded} excluded by rules/review · {values.scannerExcluded} additional scan windows excluded.</p>
                  <p className="text-xs text-muted-foreground">{values.eligible < (mlStatus?.minimumTrainingWindows || 200) ? 'Waiting for enough ordinary traffic. Empty windows and scan traffic do not build a normal baseline.' : 'Enough candidate windows. Scheduled training still checks data variation and validation before activating a model.'}</p>
                </div>)}
                <div className="text-xs text-muted-foreground mt-1">
                  Across {Object.keys(mlStatus?.eligibleWindowsByServer?.[scope] ?? {}).length} servers
                  {' · '}{mlStatus?.minimumTrainingWindows ?? '—'} required per server
                  {' · '}Active samples: {mlStatus?.models?.[scope]?.samples ?? 0}
                </div>
              </div>
            ))}
            <p className="sm:col-span-2 text-xs text-muted-foreground">Server window: {mlStatus?.trafficWindowSeconds?.server ?? '—'} seconds of site traffic. Source window: {mlStatus?.trafficWindowSeconds?.source ?? '—'} seconds from one IP. Training: {mlStatus?.trainingScheduleUtc ?? '—'}. Many requests in one busy window still count as one sample.</p>
            <div className="rounded border border-border p-3 sm:col-span-2 grid gap-2 sm:grid-cols-2">
              <div>Window scorer: <span className="text-muted-foreground">{heartbeatTime(mlStatus?.scorerLastSeen)}</span></div>
              <div>Incident grouping: <span className="text-muted-foreground">{heartbeatTime(mlStatus?.grouperLastSeen)}</span></div>
              <div>Celery Beat + worker: <span className="text-muted-foreground">{heartbeatTime(mlStatus?.celeryPipelineLastSeen)}</span></div>
              <div>Collector last seen: <span className="text-muted-foreground">{
                mlStatus?.collectorLastSeen ? new Date(mlStatus.collectorLastSeen).toLocaleString() : 'No collector heartbeat'
              }</span></div>
            </div>
            {mlStatus?.recentRuns && mlStatus.recentRuns.length > 0 && (
              <div className="rounded border border-border p-3 sm:col-span-2">
                <div className="uppercase text-xs text-muted-foreground mb-2">Recent training runs</div>
                <div className="space-y-1">
                  {mlStatus.recentRuns.map((run, index) => (
                    <div key={`${run.scope}-${run.serverId}-${run.trainedAt ?? index}`} className="break-words">
                      {run.serverId} · {run.scope} · {run.status} · {run.samples} samples
                      {run.trainedAt ? ` · ${new Date(run.trainedAt).toLocaleString()}` : ''}
                      {run.error ? ` · ${run.error}` : ''}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
