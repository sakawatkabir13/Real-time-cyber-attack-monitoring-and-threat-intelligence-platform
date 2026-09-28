import { useState, useEffect, useRef } from 'react';
import { useAppStore } from '../store/appStore';

export interface ThreatEvent {
  id: string;
  server_id: string;
  source_ip: string;
  dest_port: number | null;
  method?: string | null;
  path?: string | null;
  status_code?: number | null;
  host?: string | null;
  attack_type: string;
  severity: string;
  country: string;
  city?: string | null;
  lat: number | null;
  lng: number | null;
  dest_lat?: number | null;
  dest_lng?: number | null;
  timestamp: string;
  explanation?: string | null;
  anomaly_score?: number | null;
}

export interface Stats {
  totalThreats: number;
  attacksPerSecond: number;
  criticalAlerts: number;
  uniqueIPs: number;
  topAttackTypes: { type: string; count: number }[];
  threatsByHour: { hour: string; count: number }[];
}

export const isMlAnomaly = (event: ThreatEvent) =>
  event.attack_type === 'server_traffic_anomaly' || event.attack_type === 'source_behavior_anomaly';

export function mergeThreatEvents(
  current: ThreatEvent[],
  incoming: ThreatEvent[],
  limit = 500,
): ThreatEvent[] {
  const byId = new Map(current.map((event) => [event.id, event]));
  for (const event of incoming) byId.set(event.id, event);
  return [...byId.values()]
    .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp) || b.id.localeCompare(a.id))
    .slice(0, limit);
}

const emptyStats: Stats = {
  totalThreats: 0,
  attacksPerSecond: 0,
  criticalAlerts: 0,
  uniqueIPs: 0,
  topAttackTypes: [],
  threatsByHour: [],
};

export function useThreatFeed() {
  const [events, setEvents] = useState<ThreatEvent[]>([]);
  const [mlEvents, setMlEvents] = useState<ThreatEvent[]>([]);
  const [stats, setStats] = useState<Stats>(emptyStats);
  const [liveEvent, setLiveEvent] = useState<ThreatEvent | null>(null);
  const ws = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<number | null>(null);
  const autoRefresh = useAppStore((state) => state.settings.autoRefresh);

  useEffect(() => {
    let cancelled = false;
    const loadEvents = async (url: string, update: (events: ThreatEvent[]) => void) => {
      try {
        const response = await fetch(url);
        if (!response.ok) return;
        const fetched = await response.json() as ThreatEvent[];
        if (!cancelled) update(fetched);
      } catch (error) {
        console.error(error);
      }
    };
    const loadThreats = () => loadEvents('/api/events?limit=500',
      (fetched) => setEvents((current) => mergeThreatEvents(current, fetched)));
    const loadMlEvents = () => loadEvents('/api/events?ml_only=true&limit=20',
      (fetched) => setMlEvents((current) => mergeThreatEvents(current, fetched, 20)));
    const loadStats = async () => {
      try {
        const response = await fetch('/api/stats');
        if (response.ok) {
          const data = await response.json() as Stats;
          if (!cancelled) setStats(data);
        }
      } catch (error) {
        console.error(error);
      }
    };

    void loadThreats();
    void loadMlEvents();
    void loadStats();
    if (!autoRefresh) return () => { cancelled = true; };

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    const connectWs = () => {
      if (cancelled) return;
      try {
        const socket = new WebSocket(wsUrl);
        ws.current = socket;
        socket.onopen = () => {
          // Fetch the recent snapshot again after every reconnection.
          void loadThreats();
          void loadMlEvents();
          void loadStats();
          void useAppStore.getState().loadAlerts();
        };
        socket.onmessage = (message) => {
          try {
            const data = JSON.parse(message.data);
            if (data.type === 'NEW_THREAT') {
              const event = data.data as ThreatEvent;
              setLiveEvent(event);
              setEvents((current) => mergeThreatEvents(current, [event]));
              if (isMlAnomaly(event)) {
                setMlEvents((current) => mergeThreatEvents(current, [event], 20));
              }
            } else if (data.type === 'ALERT_CREATED' || data.type === 'ALERT_UPDATED') {
              useAppStore.getState().upsertAlert(data.data);
            }
          } catch (error) {
            console.error('WS parse error', error);
          }
        };
        socket.onclose = () => {
          if (!cancelled) reconnectTimer.current = window.setTimeout(connectWs, 3000);
        };
      } catch (error) {
        console.error('WS connection error', error);
        if (!cancelled) reconnectTimer.current = window.setTimeout(connectWs, 3000);
      }
    };
    connectWs();
    const statsInterval = window.setInterval(() => { void loadStats(); }, 5000);
    const backfillInterval = window.setInterval(() => {
      void loadThreats();
      void loadMlEvents();
    }, 30000);
    return () => {
      cancelled = true;
      window.clearInterval(statsInterval);
      window.clearInterval(backfillInterval);
      if (reconnectTimer.current !== null) window.clearTimeout(reconnectTimer.current);
      if (ws.current) {
        ws.current.onclose = null;
        ws.current.close();
      }
    };
  }, [autoRefresh]);

  return { events, mlEvents, stats, liveEvent };
}
