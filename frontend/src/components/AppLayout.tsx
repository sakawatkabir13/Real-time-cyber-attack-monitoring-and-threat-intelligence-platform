import { useEffect, useState } from 'react';
import { Shield, Search, Globe, Bell, Activity, Settings, FileText, LogOut } from 'lucide-react';

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
  const [healthy, setHealthy] = useState<boolean | null>(null);

  useEffect(() => {
    fetch('/api/health')
      .then((response) => setHealthy(response.ok))
      .catch(() => setHealthy(false));
  }, []);

  const logout = async () => {
    await fetch('/api/auth/logout', { method: 'POST' });
    window.location.reload();
  };

  return (
    <div className="flex h-screen overflow-hidden bg-background cyber-grid">
      {/* Sidebar */}
      <aside className="w-64 shrink-0 border-r border-border bg-card/80 backdrop-blur-sm flex flex-col">
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
              <p className="text-xs text-muted-foreground font-mono">v2.1.0 // ACTIVE</p>
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
            <div className={`h-2 w-2 rounded-full ${healthy ? 'bg-success animate-pulse' : healthy === false ? 'bg-destructive' : 'bg-muted-foreground'}`} />
            <span>{healthy ? 'System Online' : healthy === false ? 'System Degraded' : 'Checking System'}</span>
          </div>
          <button onClick={logout} className="mt-3 flex items-center gap-2 text-xs font-mono text-muted-foreground hover:text-foreground">
            <LogOut className="h-3.5 w-3.5" /> Sign out
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto">
        {children}
      </main>
    </div>
  );
}
