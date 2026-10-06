import { useThreatFeed } from '@/hooks/useThreatFeed';
import { useDetectionViewStore } from '@/store/detectionViewStore';

// Both pages must use the same query scope, defaults, and live-event filters.
export function useDetectionViewFeed() {
  const { hours, serverId } = useDetectionViewStore();
  return { ...useThreatFeed({ hours, serverId }), hours, serverId };
}
