import { useState, useEffect } from 'react';
import { ThreatEvent } from '@/hooks/useThreatFeed';
import { ComposableMap, Geographies, Geography, Marker, Line, ZoomableGroup } from 'react-simple-maps';
import { motion, AnimatePresence } from 'framer-motion';
import countries from 'world-atlas/countries-110m.json';

interface ThreatMapProps {
  events: ThreatEvent[];
  liveEvent: ThreatEvent | null;
}

// Norse style colors
const severityColors: Record<string, string> = {
  low: '#00f3ff',     // Cyan
  medium: '#00ff66',  // Neon Green
  high: '#ffcc00',    // Yellow
  critical: '#ff003c',// Red
};

export default function ThreatMap({ events, liveEvent }: ThreatMapProps) {
  const [liveDots, setLiveDots] = useState<ThreatEvent[]>([]);

  useEffect(() => {
    if (liveEvent) {
      setLiveDots((prev) => [liveEvent, ...prev].slice(0, 30));
    }
  }, [liveEvent]);

  return (
    <div className="relative w-full h-full min-h-[400px] bg-black overflow-hidden flex items-center justify-center">
      <style>{`
        @keyframes dash {
          to { stroke-dashoffset: 0; }
        }
        .projectile-line {
          stroke-dasharray: 400;
          stroke-dashoffset: 400;
          animation: dash 1s ease-out forwards;
        }
      `}</style>
      
      <ComposableMap
        projection="geoMercator"
        projectionConfig={{ scale: 150 }}
        className="w-full h-full"
      >
        <ZoomableGroup center={[0, 0]} zoom={1} maxZoom={8}>
          <Geographies geography={countries}>
            {({ geographies }) =>
              geographies.map((geo) => (
                <Geography
                  key={geo.rsmKey}
                  geography={geo}
                  fill="#000000" 
                  stroke="#005566" // Dark teal outline
                  strokeWidth={0.8}
                  style={{
                    default: { outline: "none" },
                    hover: { fill: "#001122", outline: "none" },
                    pressed: { outline: "none" },
                  }}
                />
              ))
            }
          </Geographies>
          
          {/* Background historical dots */}
          {events.filter((e) => e.lat !== null && e.lng !== null).slice(0, 100).map((e) => (
            <Marker key={e.id + '-bg'} coordinates={[e.lng, e.lat]}>
              <circle
                r={1.5}
                fill={severityColors[e.severity] || severityColors.low}
                opacity={0.15}
              />
            </Marker>
          ))}

          <AnimatePresence>
            {liveDots.map((dot, i) => {
              if (dot.lat === null || dot.lng === null) return null;
              const color = severityColors[dot.severity] || severityColors.low;
              const isRecent = i < 5;
              const hasTarget = dot.dest_lat != null && dot.dest_lng != null;
              return (
                <g key={`group-${dot.id}`}>
                  {/* Arc to target */}
                  {isRecent && hasTarget && (
                    <Line
                      from={[dot.lng, dot.lat]}
                      to={[dot.dest_lng, dot.dest_lat]}
                      stroke={color}
                      strokeWidth={1.5}
                      strokeLinecap="round"
                      className="projectile-line"
                      style={{
                        opacity: 0.8 - (i * 0.15)
                      }}
                    />
                  )}
                  
                  {/* Origin Marker */}
                  <Marker coordinates={[dot.lng, dot.lat]}>
                    <motion.circle
                      initial={{ r: 0, opacity: 1 }}
                      animate={{ r: isRecent ? 3 : 1.5, opacity: isRecent ? 1 : 0.4 }}
                      fill={color}
                    />
                    {/* Expanding Rings for most recent attacks */}
                    {isRecent && (
                      <>
                        <motion.circle
                          initial={{ r: 3, opacity: 1 }}
                          animate={{ r: 30, opacity: 0 }}
                          transition={{ duration: 1.5, repeat: Infinity, ease: 'easeOut' }}
                          fill="none"
                          stroke={color}
                          strokeWidth={1.5}
                        />
                        <motion.circle
                          initial={{ r: 3, opacity: 1 }}
                          animate={{ r: 50, opacity: 0 }}
                          transition={{ duration: 2, repeat: Infinity, ease: 'easeOut', delay: 0.4 }}
                          fill="none"
                          stroke={color}
                          strokeWidth={1}
                        />
                      </>
                    )}
                  </Marker>
                </g>
              );
            })}
            
          </AnimatePresence>
        </ZoomableGroup>
      </ComposableMap>
    </div>
  );
}
