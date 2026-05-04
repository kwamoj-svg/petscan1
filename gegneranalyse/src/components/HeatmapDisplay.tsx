'use client';

import { PlayerTracking } from '@/types/analysis';
import { useEffect, useRef, useState } from 'react';

interface HeatmapDisplayProps {
  players: PlayerTracking[];
  selectedPlayer?: string;
}

const CANVAS_W = 340;
const CANVAS_H = 500;
const PAD = 10;

function drawPitchOutline(ctx: CanvasRenderingContext2D) {
  ctx.strokeStyle = '#2d6b3f';
  ctx.lineWidth = 1.5;
  ctx.fillStyle = '#1a472a';

  // Pitch rect
  ctx.fillRect(PAD, PAD, CANVAS_W - 2 * PAD, CANVAS_H - 2 * PAD);
  ctx.strokeRect(PAD, PAD, CANVAS_W - 2 * PAD, CANVAS_H - 2 * PAD);

  // Halfway line
  ctx.beginPath();
  ctx.moveTo(PAD, CANVAS_H / 2);
  ctx.lineTo(CANVAS_W - PAD, CANVAS_H / 2);
  ctx.stroke();

  // Center circle
  ctx.beginPath();
  ctx.arc(CANVAS_W / 2, CANVAS_H / 2, 40, 0, Math.PI * 2);
  ctx.stroke();

  // Bottom penalty area
  ctx.strokeRect(CANVAS_W / 2 - 65, CANVAS_H - PAD - 70, 130, 70);

  // Top penalty area
  ctx.strokeRect(CANVAS_W / 2 - 65, PAD, 130, 70);
}

function drawHeatmap(ctx: CanvasRenderingContext2D, points: [number, number][]) {
  if (points.length === 0) return;

  // Create an offscreen canvas for the heatmap
  const offscreen = document.createElement('canvas');
  offscreen.width = CANVAS_W;
  offscreen.height = CANVAS_H;
  const offCtx = offscreen.getContext('2d')!;

  // Draw each point as a radial gradient dot
  points.forEach(([px, py]) => {
    const nx = px > 1 ? px / 100 : px;
    const ny = py > 1 ? py / 100 : py;
    const x = PAD + nx * (CANVAS_W - 2 * PAD);
    const y = CANVAS_H - PAD - ny * (CANVAS_H - 2 * PAD);

    const gradient = offCtx.createRadialGradient(x, y, 0, x, y, 20);
    gradient.addColorStop(0, 'rgba(255, 0, 0, 0.15)');
    gradient.addColorStop(0.5, 'rgba(255, 165, 0, 0.08)');
    gradient.addColorStop(1, 'rgba(0, 0, 255, 0)');

    offCtx.fillStyle = gradient;
    offCtx.beginPath();
    offCtx.arc(x, y, 20, 0, Math.PI * 2);
    offCtx.fill();
  });

  ctx.drawImage(offscreen, 0, 0);
}

export default function HeatmapDisplay({ players, selectedPlayer: initialSelected }: HeatmapDisplayProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [selectedId, setSelectedId] = useState<string>(initialSelected ?? players[0]?.player_id ?? '');

  const selected = players.find((p) => p.player_id === selectedId);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    ctx.clearRect(0, 0, CANVAS_W, CANVAS_H);
    drawPitchOutline(ctx);

    if (selected) {
      drawHeatmap(ctx, selected.heatmap_data);
    }
  }, [selected]);

  return (
    <div className="bg-scout-card border border-scout-border rounded-xl p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-100">Heatmap</h3>
        <select
          value={selectedId}
          onChange={(e) => setSelectedId(e.target.value)}
          className="bg-scout-dark border border-scout-border rounded-lg px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-scout-accent"
        >
          {players.map((p) => (
            <option key={p.player_id} value={p.player_id}>
              #{p.jersey_number} – {p.position_label}
            </option>
          ))}
        </select>
      </div>

      <div className="flex justify-center">
        <canvas
          ref={canvasRef}
          width={CANVAS_W}
          height={CANVAS_H}
          className="rounded-lg"
          style={{ maxWidth: '100%', height: 'auto' }}
        />
      </div>
    </div>
  );
}
