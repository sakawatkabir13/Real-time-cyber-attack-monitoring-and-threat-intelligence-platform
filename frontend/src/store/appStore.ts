import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export type ReviewVerdict = 'confirmed_malicious' | 'legitimate' | 'misconfiguration' | 'uncertain';

export interface Alert {
  id: string;
  serverId: string;
  sourceIp: string;
  targetIp: string;
  type: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  status: 'new' | 'acknowledged' | 'resolved';
  timestamp: string;
  lastSeen: string;
  message?: string;
  explanation?: string;
  anomaly_score?: number;
  occurrenceCount: number;
  acknowledged?: boolean;
  acknowledgedAt?: string | null;
  verdict: ReviewVerdict | 'unreviewed';
  reviewVersion: number;
  reviewedAt?: string | null;
  reviewNotes?: string;
  incidentGroupId?: string | null;
}

type BackendAlert = Omit<Alert, 'severity'> & { severity: string };

function normalizeAlert(alert: BackendAlert): Alert {
  const value = alert.severity.toLowerCase();
  const severity = value === 'critical' ? 'Critical'
    : value === 'high' ? 'High'
      : value === 'medium' ? 'Medium' : 'Low';
  return { ...alert, severity, verdict: alert.verdict ?? 'unreviewed', reviewVersion: alert.reviewVersion ?? 0 };
}

interface AppState {
  alerts: Alert[];
  alertsLoading: boolean;
  loadAlerts: () => Promise<void>;
  upsertAlert: (alert: BackendAlert) => void;
  acknowledgeAlert: (id: string) => Promise<boolean>;
  resolveAlert: (id: string) => Promise<boolean>;
  reviewAlert: (id: string, verdict: ReviewVerdict, notes: string, expectedVersion: number) => Promise<string | null>;
  settings: {
    theme: 'dark' | 'light';
    autoRefresh: boolean;
    alertSensitivity: 'low' | 'medium' | 'high' | 'critical';
  };
  updateSettings: (settings: Partial<AppState['settings']>) => void;
}

export const useAppStore = create<AppState>()(
  persist(
    (set) => ({
      alerts: [],
      alertsLoading: false,
      loadAlerts: async () => {
        set({ alertsLoading: true });
        try {
          const response = await fetch('/api/alerts?limit=500');
          if (!response.ok) throw new Error(`Alert request failed (${response.status})`);
          const alerts = (await response.json() as BackendAlert[]).map(normalizeAlert);
          set({ alerts });
        } catch (error) {
          console.error(error);
        } finally {
          set({ alertsLoading: false });
        }
      },
      upsertAlert: (incoming) => set((state) => {
        const alert = normalizeAlert(incoming);
        const existing = state.alerts.findIndex((item) => item.id === alert.id);
        if (existing === -1) return { alerts: [alert, ...state.alerts].slice(0, 500) };
        const alerts = [...state.alerts];
        alerts[existing] = alert;
        alerts.sort((a, b) => Date.parse(b.lastSeen) - Date.parse(a.lastSeen));
        return { alerts };
      }),
      acknowledgeAlert: async (id) => {
        try {
          const response = await fetch(`/api/alerts/${encodeURIComponent(id)}/acknowledge`, {
            method: 'PATCH',
          });
          if (!response.ok) throw new Error(`Acknowledge failed (${response.status})`);
          const alert = normalizeAlert(await response.json() as BackendAlert);
          set((state) => ({
            alerts: state.alerts.map((item) => item.id === id ? alert : item),
          }));
          return true;
        } catch (error) {
          console.error(error);
          return false;
        }
      },
      resolveAlert: async (id) => {
        try {
          const response = await fetch(`/api/alerts/${encodeURIComponent(id)}/resolve`, {
            method: 'PATCH',
          });
          if (!response.ok) throw new Error(`Resolve failed (${response.status})`);
          const alert = normalizeAlert(await response.json() as BackendAlert);
          set((state) => ({
            alerts: state.alerts.map((item) => item.id === id ? alert : item),
          }));
          return true;
        } catch (error) {
          console.error(error);
          return false;
        }
      },
      reviewAlert: async (id, verdict, notes, expectedVersion) => {
        try {
          const response = await fetch(`/api/alerts/${encodeURIComponent(id)}/review`, {
            method: 'PATCH', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ verdict, notes, expected_version: expectedVersion }),
          });
          if (response.status === 409) return 'Another review was saved. Reload the current verdict before trying again.';
          if (!response.ok) return `Review could not be saved (${response.status}). Your notes have been kept here.`;
          const alert = normalizeAlert(await response.json() as BackendAlert);
          set((state) => ({ alerts: state.alerts.map((item) => item.id === id ? alert : item) }));
          return null;
        } catch {
          return 'Network error. Your review was not confirmed saved; retry or reload its history.';
        }
      },
      settings: {
        theme: 'dark',
        autoRefresh: true,
        alertSensitivity: 'high',
      },
      updateSettings: (newSettings) =>
        set((state) => ({ settings: { ...state.settings, ...newSettings } })),
    }),
    {
      name: 'vanguard-app-storage',
      partialize: (state) => ({ settings: state.settings }) as AppState,
      merge: (persisted, current) => {
        const saved = persisted as Partial<AppState>;
        return { ...current, settings: saved.settings ?? current.settings };
      },
    },
  ),
);
