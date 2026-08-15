import { useState, useEffect, useRef } from 'react';
import { useAppStore } from '../store/appStore';

export interface ThreatEvent {
  id: string;
  server_id: string;
  source_ip: string;
  dest_port: number;
  attack_type: string;
  severity: string;
  country: string;
  city?: string | null;
  lat: number | null;
  lng: number | null;
  dest_lat?: number | null;
  dest_lng?: number | null;
  timestamp: string;
  explanation?: string;
  anomaly_score?: number;
}

export interface Stats {
  totalThreats: number;
  attacksPerSecond: number;
  criticalAlerts: number;
  uniqueIPs: number;
  topAttackTypes: { type: string; count: number }[];
  threatsByHour: { hour: string; count: number }[];
}

export function useThreatFeed() {
  const [events, setEvents] = useState<ThreatEvent[]>([]);
  const [stats, setStats] = useState<Stats>({
    totalThreats: 0,
    attacksPerSecond: 0,
    criticalAlerts: 0,
    uniqueIPs: 0,
    topAttackTypes: [],
    threatsByHour: [],
  });
  const [liveEvent, setLiveEvent] = useState<ThreatEvent | null>(null);
  const ws = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<number | null>(null);
  const autoRefresh = useAppStore((state) => state.settings.autoRefresh);

  useEffect(() => {
    loadThreats();
    loadStats();
    
    if (!autoRefresh) return;
    let cancelled = false;
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    const connectWs = () => {
      if (cancelled) return;
      ws.current = new WebSocket(wsUrl);
      
      ws.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'NEW_THREAT') {
            setLiveEvent(data.data);
            setEvents(prev => [data.data, ...prev].slice(0, 500));
            
          } else if (data.type === 'ALERT_CREATED' || data.type === 'ALERT_UPDATED') {
            useAppStore.getState().upsertAlert(data.data);
          }
        } catch (e) {
          console.error("WS parse error", e);
        }
      };

      ws.current.onclose = () => {
        if (!cancelled) reconnectTimer.current = window.setTimeout(connectWs, 3000);
      };
    };

    connectWs();
    
    return () => {
      cancelled = true;
      if (reconnectTimer.current !== null) window.clearTimeout(reconnectTimer.current);
      if (ws.current) {
        ws.current.onclose = null;
        ws.current.close();
      }
    };
  }, [autoRefresh]);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = window.setInterval(loadStats, 5000);
    return () => clearInterval(interval);
  }, [autoRefresh]);

  async function loadThreats() {
    try {
      const res = await fetch('/api/events');
      if (res.ok) {
        const data = await res.json();
        setEvents(data);
      }
    } catch (e) {
      console.error(e);
    }
  }

  async function loadStats() {
    try {
      const res = await fetch('/api/stats');
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (e) {
      console.error(e);
    }
  }

  return {
    events,
    stats,
    liveEvent,
  };
}
