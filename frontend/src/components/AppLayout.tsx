import { useState } from 'react';
import { Shield, Search, Globe, Bell, Activity, Settings, FileText, LogOut, Menu } from 'lucide-react';
import { useSystemHealth } from '@/hooks/useSystemHealth';
import EventInspector from '@/components/EventInspector';
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog';

const NAV_ITEMS = [
  { to: '/', icon: Activity, label: 'Dashboard' },
  { to: '/analyzer', icon: FileText, label: 'Log Analyzer' },
  { to: '/ip-lookup', icon: Search, label: 'IP Lookup' },
  { to: '/map', icon: Globe, label: 'Threat Map' },
  { to: '/alerts', icon: Bell, label: 'Alerts' },
  { to: '/settings', icon: Settings, label: 'Settings' },
];

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const pathname = window.location.pathname;
  const [menuOpen, setMenuOpen] = useState(false);
  const { health, checkedAt, unavailable } = useSystemHealth();
  const healthy = health && Object.values(health.checks).every(Boolean)
    && ['websocketRelay', 'windowScorer', 'incidentGrouping', 'celeryBeatWorker', 'collectorFresh'].every((key) => health.background[key as keyof typeof health.background] === true);

  const logout = async () => {
    await fetch('/api/auth/logout', { method: 'POST' });
    window.location.reload();
  };

  const sidebar = <>
        <div className="p-6 border-b border-border">
          <div className="flex items-center gap-3">
            <div className="relative">
              <Shield className="h-8 w-8 text-primary" />
              <div className="absolute inset-0 animate-pulse-glow">
                <Shield className="h-8 w-8 text-primary opacity-50" />
              </div>
            </div>
            <div>
              <h1 className="text-lg font-bold font-display text-primary text-glow tracking-wider">
                VANGUARD-360
              </h1>
              <p className="text-xs text-muted-foreground font-mono">HTTP security monitoring</p>
            </div>
          </div>
        </div>

        <nav className="flex-1 p-4 space-y-1">
          {NAV_ITEMS.map(({ to, icon: Icon, label }) => {
            const isActive = pathname === to;
            return (
              <a
                key={to}
                href={to}
                aria-current={isActive ? 'page' : undefined}
                className={`flex items-center gap-3 px-4 py-3 rounded-md font-mono text-sm transition-all duration-200 ${
                  isActive
                    ? 'bg-primary/10 text-primary border border-primary/20 glow-primary'
                    : 'text-muted-foreground hover:text-foreground hover:bg-muted/50'
                }`}
              >
                <Icon className="h-4 w-4" />
                {label}
              </a>
            );
          })}
        </nav>

        <div className="p-4 border-t border-border">
          <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
            <div className={`h-2 w-2 rounded-full ${unavailable ? 'bg-destructive' : healthy ? 'bg-success' : 'bg-warning'}`} />
            <span role="status">{unavailable ? 'Health unavailable' : healthy ? 'Pipeline healthy' : health ? 'Pipeline needs attention' : 'Checking system'}</span>
          </div>
          {health && <div className="mt-2 space-y-1 text-xs text-muted-foreground">
            <p>ML: {health.background.modelState === 'warming_up' ? 'Collecting baseline' : health.background.modelFresh === false ? 'Model stale' : 'Ready'}</p>
            <p>Collector: {health.background.collectorFresh ? 'Connected' : 'No fresh heartbeat'}</p>
            <p>{checkedAt && `Checked ${new Date(checkedAt).toLocaleTimeString()}`}</p>
          </div>}
          <button onClick={logout} className="mt-3 flex min-h-10 items-center gap-2 text-sm font-mono text-muted-foreground hover:text-foreground">
            <LogOut className="h-3.5 w-3.5" /> Sign out
          </button>
        </div>
    </>;
  return (
    <EventInspector>
    <div className="flex h-dvh overflow-hidden bg-background cyber-grid">
      <a href="#main-content" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[100] focus:rounded focus:bg-card focus:p-3">Skip to content</a>
      <aside className="hidden w-64 shrink-0 border-r border-border bg-card/80 backdrop-blur-sm md:flex md:flex-col">{sidebar}</aside>
      <Dialog open={menuOpen} onOpenChange={setMenuOpen}>
        <DialogContent className="left-0 top-0 h-dvh w-72 max-w-[90vw] translate-x-0 translate-y-0 gap-0 overflow-y-auto p-0">
          <DialogTitle className="sr-only">Navigation</DialogTitle>
          <DialogDescription className="sr-only">Navigate Vanguard pages and check pipeline status.</DialogDescription>
          {sidebar}
        </DialogContent>
      </Dialog>
      <main id="main-content" className="min-w-0 flex-1 overflow-auto">
        <div className="sticky top-0 z-30 flex items-center gap-3 border-b border-border bg-card px-4 py-2 md:hidden">
          <button aria-label="Open navigation" onClick={() => setMenuOpen(true)} className="rounded p-3 hover:bg-muted"><Menu className="h-5 w-5" /></button>
          <span className="font-semibold text-primary">VANGUARD-360</span>
        </div>
        {children}
      </main>
    </div>
    </EventInspector>
  );
}
