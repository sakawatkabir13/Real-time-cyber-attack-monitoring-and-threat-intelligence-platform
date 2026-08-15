import { lazy, Suspense, useEffect } from 'react';
import { Toaster } from '@/components/ui/toaster';
import { Toaster as Sonner } from '@/components/ui/sonner';
import { TooltipProvider } from '@/components/ui/tooltip';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import AuthGate from '@/components/AuthGate';
import AppLayout from '@/components/AppLayout';
import { useAppStore } from '@/store/appStore';
import AlertSync from '@/components/AlertSync';

const Dashboard = lazy(() => import('@/pages/Dashboard'));
const IPLookup = lazy(() => import('@/pages/IPLookup'));
const MapPage = lazy(() => import('@/pages/MapPage'));
const AlertsPage = lazy(() => import('@/pages/AlertsPage'));
const SettingsPage = lazy(() => import('@/pages/SettingsPage'));
const LogAnalyzerPage = lazy(() => import('@/pages/LogAnalyzerPage'));
const NotFound = lazy(() => import('@/pages/NotFound'));
const queryClient = new QueryClient();

function ThemeSync() {
  const theme = useAppStore((state) => state.settings.theme);
  useEffect(() => {
    document.documentElement.classList.toggle('light', theme === 'light');
    document.documentElement.classList.toggle('dark', theme === 'dark');
  }, [theme]);
  return null;
}

export default function App() {
  const pages: Record<string, React.LazyExoticComponent<() => JSX.Element>> = {
    '/': Dashboard,
    '/ip-lookup': IPLookup,
    '/analyzer': LogAnalyzerPage,
    '/map': MapPage,
    '/alerts': AlertsPage,
    '/settings': SettingsPage,
  };
  const Page = pages[window.location.pathname] || NotFound;
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <ThemeSync />
        <Toaster />
        <Sonner />
        <AuthGate>
          <AlertSync />
          <AppLayout>
            <Suspense fallback={<div className="p-8 font-mono text-muted-foreground">Loading…</div>}>
              <Page />
            </Suspense>
          </AppLayout>
        </AuthGate>
      </TooltipProvider>
    </QueryClientProvider>
  );
}
