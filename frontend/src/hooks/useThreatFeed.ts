import { useState, useEffect, useRef, useCallback } from 'react';
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

export type SubscribeToDetections = (listener: (event: ThreatEvent) => void) => () => void;

export interface Stats {
  totalThreats: number;
  attacksPerSecond: number;
  criticalAlerts: number;
  uniqueIPs: number;
  topAttackTypes: { type: string; count: number }[];
  threatsByHour: { hour: string; count: number }[];
  periodHours?: number;
  bucketSeconds?: number;
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

export function useThreatFeed({ hours, serverId = '' }: { hours?: number; serverId?: string } = {}) {
  const [events, setEvents] = useState<ThreatEvent[]>([]);
  const [mlEvents, setMlEvents] = useState<ThreatEvent[]>([]);
  const [stats, setStats] = useState<Stats>(emptyStats);
  const [liveEvent, setLiveEvent] = useState<ThreatEvent | null>(null);
  const detectionListeners = useRef(new Set<(event: ThreatEvent) => void>());
  // Notify each arrival directly: React may batch multiple latest-event updates.
  const subscribeToDetections: SubscribeToDetections = useCallback((listener) => {
    detectionListeners.current.add(listener);
    return () => { detectionListeners.current.delete(listener); };
  }, []);
  const ws = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<number | null>(null);
  const autoRefresh = useAppStore((state) => state.settings.autoRefresh);
  const [connection, setConnection] = useState('connecting');
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [refreshVersion, setRefreshVersion] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setEvents([]); setMlEvents([]); setStats(emptyStats); setLiveEvent(null); setUpdatedAt(null); setErrors({});
    setConnection(autoRefresh ? 'connecting' : 'paused');
    const filters = new URLSearchParams();
    if (hours) filters.set('hours', String(hours));
    if (serverId) filters.set('server_id', serverId);
    const suffix = filters.size ? `&${filters}` : '';
    const loadEvents = async (url: string, update: (events: ThreatEvent[]) => void) => {
      try {
        const response = await fetch(url);
        if (!response.ok) throw new Error(`Event snapshot failed (${response.status})`);
        const fetched = await response.json() as ThreatEvent[];
        if (!cancelled) { update(fetched); setErrors((current) => ({ ...current, [url]: '' })); }
      } catch (error) {
        if (!cancelled) setErrors((current) => ({ ...current, [url]: error instanceof Error ? error.message : 'Events unavailable' }));
        console.error(error);
      }
    };
    const loadThreats = () => loadEvents('/api/events?limit=500' + suffix,
      (fetched) => setEvents((current) => mergeThreatEvents(current, fetched)));
    const loadMlEvents = () => loadEvents('/api/events?ml_only=true&limit=20' + suffix,
      (fetched) => setMlEvents((current) => mergeThreatEvents(current, fetched, 20)));
    const loadStats = async () => {
      try {
        const response = await fetch('/api/stats' + (filters.size ? `?${filters}` : ''));
        if (response.ok) {
          const data = await response.json() as Stats;
          if (!cancelled) { setStats(data); setUpdatedAt(new Date().toISOString()); setErrors((current) => ({ ...current, stats: '' })); }
        } else throw new Error(`Statistics unavailable (${response.status})`);
      } catch (error) {
        if (!cancelled) setErrors((current) => ({ ...current, stats: error instanceof Error ? error.message : 'Statistics unavailable' }));
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
          if (cancelled) return;
          setConnection('live');
          // Fetch the recent snapshot again after every reconnection.
          void loadThreats();
          void loadMlEvents();
          void loadStats();
          void useAppStore.getState().loadAlerts();
        };
        socket.onmessage = (message) => {
          if (cancelled) return;
          try {
            const data = JSON.parse(message.data);
            if (data.type === 'NEW_THREAT') {
              const event = data.data as ThreatEvent;
              if (serverId && event.server_id !== serverId) return;
              if (hours && Date.parse(event.timestamp) < Date.now() - hours * 3600000) return;
              setLiveEvent(event);
              for (const listener of detectionListeners.current) listener(event);
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
          if (!cancelled) { setConnection('disconnected'); reconnectTimer.current = window.setTimeout(connectWs, 3000); }
        };
      } catch (error) {
        if (!cancelled) setConnection('disconnected');
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
  }, [autoRefresh, hours, serverId, refreshVersion]);

  const cutoff = hours ? Date.now() - hours * 3600000 : 0;
  return { events: events.filter((event) => Date.parse(event.timestamp) >= cutoff), mlEvents: mlEvents.filter((event) => Date.parse(event.timestamp) >= cutoff), stats, liveEvent, subscribeToDetections, connection, updatedAt, error: Object.values(errors).filter(Boolean).join(' · '), refresh: () => setRefreshVersion((value) => value + 1) };
}
