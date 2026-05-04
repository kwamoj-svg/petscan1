'use client';

import { FormationData, PlayerTracking } from '@/types/analysis';
import { useState } from 'react';

interface FormationPitchProps {
  formation: FormationData;
  players?: PlayerTracking[];
}

/**
 * Parse a formation string like "4-3-3" into rows of player counts.
 * Always adds 1 GK at the back.
 */
function parseFormation(formation: string): number[] {
  const parts = formation.split('-').map(Number).filter((n) => !isNaN(n));
  return [1, ...parts]; // GK + outfield rows
}

/**
 * Given a formation string, produce player positions (x, y) in 0-100 range.
 * x = left-right, y = bottom-top (0 = own goal line, 100 = opponent goal).
 */
function generatePositions(formationStr: string): { x: number; y: number; label: string }[] {
  const rows = parseFormation(formationStr);
  const positions: { x: number; y: number; label: string }[] = [];
  const totalRows = rows.length;
  let playerNum = 1;

  rows.forEach((count, rowIdx) => {
    // y: distribute rows from 8% (GK) to 85% (forwards)
    const y = 8 + (rowIdx / (totalRows - 1)) * 77;

    for (let i = 0; i < count; i++) {
      // x: distribute evenly across width
      const x = count === 1 ? 50 : 15 + (i / (count - 1)) * 70;
      positions.push({ x, y, label: String(playerNum) });
      playerNum++;
    }
  });

  return positions;
}

/** SVG pitch dimensions */
const PITCH_W = 340;
const PITCH_H = 500;
const PAD = 10;

export default function FormationPitch({ formation, players }: FormationPitchProps) {
  const [view, setView] = useState<'with_ball' | 'without_ball'>('with_ball');

  const currentFormation =
    view === 'with_ball' ? formation.formation_with_ball : formation.formation_without_ball;

  // If we have tracking data for team B (opponent), use their avg positions
  const teamBPlayers = players?.filter((p) => p.team === 'B') ?? [];

  const positions =
    teamBPlayers.length > 0
      ? teamBPlayers.map((p) => ({
          x: p.avg_position_y * 100,
          y: p.avg_position_x * 100,
          label: p.jersey_number,
        }))
      : generatePositions(currentFormation);

  return (
    <div className="bg-scout-card border border-scout-border rounded-xl p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-100">Formation: {currentFormation}</h3>
        <div className="flex rounded-lg overflow-hidden border border-scout-border">
          <button
            onClick={() => setView('with_ball')}
            className={`px-3 py-1.5 text-xs font-medium transition-colors ${
              view === 'with_ball'
                ? 'bg-scout-accent text-white'
                : 'bg-scout-dark text-gray-400 hover:text-gray-200'
            }`}
          >
            Mit Ball
          </button>
          <button
            onClick={() => setView('without_ball')}
            className={`px-3 py-1.5 text-xs font-medium transition-colors ${
              view === 'without_ball'
                ? 'bg-scout-accent text-white'
                : 'bg-scout-dark text-gray-400 hover:text-gray-200'
            }`}
          >
            Ohne Ball
          </button>
        </div>
      </div>

      <div className="flex justify-center">
        <svg
          viewBox={`0 0 ${PITCH_W} ${PITCH_H}`}
          className="w-full max-w-sm"
          style={{ aspectRatio: `${PITCH_W}/${PITCH_H}` }}
        >
          {/* Pitch background */}
          <rect x={PAD} y={PAD} width={PITCH_W - 2 * PAD} height={PITCH_H - 2 * PAD} rx={4} fill="#1a472a" stroke="#2d6b3f" strokeWidth={2} />

          {/* Halfway line */}
          <line x1={PAD} y1={PITCH_H / 2} x2={PITCH_W - PAD} y2={PITCH_H / 2} stroke="#2d6b3f" strokeWidth={1.5} />

          {/* Center circle */}
          <circle cx={PITCH_W / 2} cy={PITCH_H / 2} r={40} fill="none" stroke="#2d6b3f" strokeWidth={1.5} />
          <circle cx={PITCH_W / 2} cy={PITCH_H / 2} r={3} fill="#2d6b3f" />

          {/* Bottom penalty area (own goal) */}
          <rect x={PITCH_W / 2 - 65} y={PITCH_H - PAD - 70} width={130} height={70} fill="none" stroke="#2d6b3f" strokeWidth={1.5} />
          <rect x={PITCH_W / 2 - 30} y={PITCH_H - PAD - 25} width={60} height={25} fill="none" stroke="#2d6b3f" strokeWidth={1.5} />

          {/* Top penalty area (opponent goal) */}
          <rect x={PITCH_W / 2 - 65} y={PAD} width={130} height={70} fill="none" stroke="#2d6b3f" strokeWidth={1.5} />
          <rect x={PITCH_W / 2 - 30} y={PAD} width={60} height={25} fill="none" stroke="#2d6b3f" strokeWidth={1.5} />

          {/* Players */}
          {positions.map((pos, idx) => {
            // Map 0-100 to pitch coordinates
            const cx = PAD + (pos.x / 100) * (PITCH_W - 2 * PAD);
            const cy = PITCH_H - PAD - (pos.y / 100) * (PITCH_H - 2 * PAD);

            return (
              <g key={idx}>
                <circle cx={cx} cy={cy} r={14} fill="#3b82f6" fillOpacity={0.85} stroke="#60a5fa" strokeWidth={1.5} />
                <text x={cx} y={cy + 1} textAnchor="middle" dominantBaseline="central" fill="white" fontSize={10} fontWeight="bold">
                  {pos.label}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}
