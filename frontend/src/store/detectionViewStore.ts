import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export type DetectionPeriod = 1 | 24 | 168;

interface DetectionViewState {
  hours: DetectionPeriod;
  serverId: string;
  setHours: (hours: DetectionPeriod) => void;
  setServerId: (serverId: string) => void;
}

// Sidebar navigation reloads the page, so persist only the shared filter choices.
// Do not persist event data, live animation queues, or authenticated responses.
export const useDetectionViewStore = create<DetectionViewState>()(persist(
  (set) => ({
    hours: 24,
    serverId: '',
    setHours: (hours) => set({ hours }),
    setServerId: (serverId) => set({ serverId }),
  }),
  {
    name: 'vanguard-detection-view',
    partialize: ({ hours, serverId }) => ({ hours, serverId }),
    merge: (persisted, current) => {
      const saved = persisted as Partial<DetectionViewState> | undefined;
      return {
        ...current,
        hours: [1, 24, 168].includes(saved?.hours ?? 0) ? saved!.hours! : 24,
        serverId: typeof saved?.serverId === 'string' && saved.serverId.length <= 64 ? saved.serverId : '',
      };
    },
  },
));
