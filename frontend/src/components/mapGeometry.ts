import type { ThreatEvent } from '@/hooks/useThreatFeed';

export type GeoPoint = [number, number];

export const severityColors: Record<string, string> = {
  normal: '#94a3b8', low: '#67e8f9', medium: '#fbbf24', high: '#fb923c', critical: '#fb4b62',
};

export function point(lng: number | null | undefined, lat: number | null | undefined): GeoPoint | null {
  if (typeof lng !== 'number' || typeof lat !== 'number' ||
      !Number.isFinite(lng) || !Number.isFinite(lat) ||
      Math.abs(lng) > 180 || Math.abs(lat) > 90) return null;
  return [lng, lat];
}

export function sourcePoint(event: ThreatEvent): GeoPoint | null {
  return point(event.lng, event.lat);
}

export function targetPoint(event: ThreatEvent, fallback: GeoPoint | null = null): GeoPoint | null {
  return point(event.dest_lng, event.dest_lat) ?? fallback;
}

export function routeCoordinates(from: GeoPoint, to: GeoPoint, lane = 0): GeoPoint[] {
  // Keep longitude continuous: independently wrapping samples at ±180° makes
  // the visible path jump backwards. The bounded bow also avoids polar loops.
  const deltaLng = to[0] - from[0];
  const deltaLat = to[1] - from[1];
  const distance = Math.hypot(deltaLng, deltaLat);
  const headroom = Math.max(1, 82 - Math.max(Math.abs(from[1]), Math.abs(to[1])));
  const bow = Math.min(headroom, Math.max(3, Math.min(14, distance * 0.07)));
  const length = Math.max(1, distance);
  const perpendicular: GeoPoint = [-deltaLat / length, deltaLng / length];
  return Array.from({ length: 49 }, (_, index) => {
    const t = index / 48;
    if (index === 0) return from;
    if (index === 48) return to;
    const arc = Math.sin(Math.PI * t);
    const baseLng = from[0] + deltaLng * t;
    const baseLat = from[1] + deltaLat * t + bow * arc;
    const laneOffset = lane * 2.4 * arc;
    return [
      Math.max(-180, Math.min(180, baseLng + perpendicular[0] * laneOffset)),
      Math.max(-82, Math.min(82, baseLat + perpendicular[1] * laneOffset)),
    ] as GeoPoint;
  });
}
