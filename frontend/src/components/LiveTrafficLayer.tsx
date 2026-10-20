import { memo, useEffect, useRef } from 'react';
import { useMapContext, useZoomPanContext } from 'react-simple-maps';
import type { SubscribeToDetections, ThreatEvent } from '@/hooks/useThreatFeed';
import { LiveMapRoutes, ROUTE_LIFETIME_MS } from './mapPlayback';
import { routeCoordinates, severityColors, sourcePoint, targetPoint } from './mapGeometry';
import type { GeoPoint } from './mapGeometry';

interface Props {
  liveEvent: ThreatEvent | null;
  subscribeToTraffic?: SubscribeToDetections;
  configuredTarget: GeoPoint | null;
  reducedMotion: boolean;
  onActiveCount: (count: number) => void;
}

interface PreparedRoute {
  path: Path2D;
  length: number;
  from: GeoPoint;
  to: GeoPoint;
}

// Share the countries' projection, clipping, pan and zoom. A canvas handles
// simultaneous arrivals without thousands of independently animated SVG nodes.
export default memo(function LiveTrafficLayer({
  liveEvent, subscribeToTraffic, configuredTarget, reducedMotion, onActiveCount,
}: Props) {
  const { width, height, projection } = useMapContext();
  const { k: zoom } = useZoomPanContext();
  const canvas = useRef<HTMLCanvasElement>(null);
  const routes = useRef(new LiveMapRoutes());
  const wake = useRef<() => void>(() => {});
  const current = useRef({ configuredTarget, reducedMotion });
  current.current = { configuredTarget, reducedMotion };

  useEffect(() => {
    const receive = (event: ThreatEvent) => {
      const target = targetPoint(event, current.current.configuredTarget);
      if (current.current.reducedMotion || !sourcePoint(event) || !target) return;
      // Resolve the fallback once: config refreshes cannot redirect an arc.
      if (routes.current.add({ ...event, dest_lng: target[0], dest_lat: target[1] }, Date.now())) wake.current();
    };
    return subscribeToTraffic?.(receive);
  }, [subscribeToTraffic]);

  useEffect(() => {
    if (subscribeToTraffic || !liveEvent || reducedMotion) return;
    const target = targetPoint(liveEvent, configuredTarget);
    if (!sourcePoint(liveEvent) || !target) return;
    if (routes.current.add({ ...liveEvent, dest_lng: target[0], dest_lat: target[1] }, Date.now())) wake.current();
  }, [liveEvent, subscribeToTraffic, configuredTarget, reducedMotion]);

  useEffect(() => {
    const element = canvas.current;
    const context = element?.getContext('2d');
    if (!element || !context) return;
    const prepared = new Map<string, PreparedRoute>();
    let frame: number | null = null;
    let lastCount = -1;
    const resize = () => {
      const bounds = element.closest('svg')?.getBoundingClientRect();
      const scale = bounds ? Math.min(bounds.width / width, bounds.height / height) : 1;
      const density = Math.max(1, Math.min(3, scale * window.devicePixelRatio * zoom));
      element.width = Math.ceil(width * density);
      element.height = Math.ceil(height * density);
      context.setTransform(density, 0, 0, density, 0, 0);
    };
    const ring = (at: GeoPoint, radius: number, opacity: number) => {
      context.globalAlpha = opacity;
      context.lineWidth = 1 / zoom;
      context.beginPath();
      context.arc(at[0], at[1], radius / zoom, 0, Math.PI * 2);
      context.stroke();
    };
    const draw = () => {
      frame = null;
      const now = Date.now();
      routes.current.expire(now);
      context.clearRect(0, 0, width, height);
      for (const id of prepared.keys()) if (!routes.current.active.has(id)) prepared.delete(id);
      context.lineCap = 'round';
      context.lineJoin = 'round';
      for (const [id, route] of routes.current.active) {
        if (reducedMotion) continue;
        let geometry = prepared.get(id);
        if (!geometry) {
          const points = routeCoordinates(sourcePoint(route.event)!, targetPoint(route.event)!, route.lane)
            .map((coordinates) => projection(coordinates) as GeoPoint);
          const path = new Path2D();
          path.moveTo(...points[0]);
          let length = 0;
          for (let index = 1; index < points.length; index += 1) {
            path.lineTo(...points[index]);
            length += Math.hypot(points[index][0] - points[index - 1][0], points[index][1] - points[index - 1][1]);
          }
          geometry = { path, length, from: points[0], to: points.at(-1)! };
          prepared.set(id, geometry);
        }
        const age = now - route.startedAt;
        context.strokeStyle = severityColors[route.event.severity] ?? severityColors.low;
        context.setLineDash([]);
        context.lineWidth = 1.15 / zoom;
        context.globalAlpha = 0.28 * Math.min(1, (ROUTE_LIFETIME_MS - age) / 650);
        context.stroke(geometry.path);
        if (age < 1250) {
          const progress = age / 1250;
          context.globalAlpha = Math.min(0.98, progress * 12, (1 - progress) * 8);
          context.lineWidth = 3.4 / zoom;
          context.setLineDash([geometry.length * 0.055, geometry.length * 0.945]);
          context.lineDashOffset = -progress * geometry.length * 0.95;
          context.stroke(geometry.path);
          context.setLineDash([]);
          context.lineDashOffset = 0;
        }
        if (route.event.severity !== 'normal' && age < 800) {
          ring(geometry.from, 2 + age / 80, 0.95 * (1 - age / 800));
        }
        if (age > 950 && age < 2050) {
          const progress = (age - 950) / 1100;
          ring(geometry.to, 2.5 + progress * 12.5, 0.9 * (1 - progress));
        }
      }
      context.globalAlpha = 1;
      const count = reducedMotion ? 0 : routes.current.active.size;
      if (lastCount !== count) { lastCount = count; onActiveCount(count); }
      if (routes.current.active.size) frame = window.requestAnimationFrame(draw);
    };
    const schedule = () => { if (frame === null) frame = window.requestAnimationFrame(draw); };
    wake.current = schedule;
    const observer = new ResizeObserver(() => { resize(); schedule(); });
    observer.observe(element.closest('svg')!);
    resize();
    schedule();
    // Background tabs never build a playback backlog: expire by wall clock on
    // return, then render only arrivals still within their visual lifetime.
    document.addEventListener('visibilitychange', schedule);
    return () => {
      if (frame !== null) window.cancelAnimationFrame(frame);
      observer.disconnect();
      document.removeEventListener('visibilitychange', schedule);
      wake.current = () => {};
    };
  }, [width, height, projection, zoom, reducedMotion, onActiveCount]);

  return (
    <foreignObject x={0} y={0} width={width} height={height} pointerEvents="none" aria-hidden="true">
      <canvas ref={canvas} style={{ display: 'block', width, height }} data-testid="live-traffic-canvas" />
    </foreignObject>
  );
});
