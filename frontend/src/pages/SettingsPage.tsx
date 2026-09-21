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

  useEffect(() => {
    fetch('/api/ml/status')
      .then((response) => response.ok ? response.json() : Promise.reject(response))
      .then((data) => setMlStatus(data as MlStatus))
      .catch(() => setMlStatus(null));
  }, []);

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
              Security Thresholds
            </CardTitle>
            <CardDescription>Choose which persisted incidents appear in alert views.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label className="font-mono">Alert Sensitivity (Beta)</Label>
              <select
                value={settings.alertSensitivity}
                onChange={(event) => updateSettings({ alertSensitivity: event.target.value as typeof settings.alertSensitivity })}
                className="w-full bg-background border border-border rounded-md px-3 py-2 font-mono text-sm"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical Only</option>
              </select>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/50 border-border md:col-span-2">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <BrainCircuit className="w-5 h-5 text-primary" />
              Behavioral ML
            </CardTitle>
            <CardDescription>Models train only from real, rule-clean traffic windows.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3 sm:grid-cols-2 font-mono text-sm">
            <div>Status: <span className="text-primary">{mlStatus?.state ?? 'unavailable'}</span></div>
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
                  {mlStatus?.eligibleWindows?.[scope] ?? 0} eligible windows
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  Across {Object.keys(mlStatus?.eligibleWindowsByServer?.[scope] ?? {}).length} servers
                  {' · '}{mlStatus?.minimumTrainingWindows ?? '—'} required per server
                  {' · '}Active samples: {mlStatus?.models?.[scope]?.samples ?? 0}
                </div>
              </div>
            ))}
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
