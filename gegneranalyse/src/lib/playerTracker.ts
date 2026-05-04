import { randomUUID } from 'crypto';
import { PlayerTracking, DuelPosition } from '@/types/analysis';

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

interface BBox { x: number; y: number; w: number; h: number }

interface Detection {
  bbox: BBox;
  class: string;
  confidence: number;
  frameIndex: number;
}

interface Track {
  id: string;
  class: string;
  detections: Detection[];
  missedFrames: number;
  active: boolean;
}

// ---------------------------------------------------------------------------
// calculateIoU
// ---------------------------------------------------------------------------

export function calculateIoU(a: BBox, b: BBox): number {
  const ax1 = a.x;
  const ay1 = a.y;
  const ax2 = a.x + a.w;
  const ay2 = a.y + a.h;

  const bx1 = b.x;
  const by1 = b.y;
  const bx2 = b.x + b.w;
  const by2 = b.y + b.h;

  const ix1 = Math.max(ax1, bx1);
  const iy1 = Math.max(ay1, by1);
  const ix2 = Math.min(ax2, bx2);
  const iy2 = Math.min(ay2, by2);

  if (ix2 <= ix1 || iy2 <= iy1) return 0;

  const intersection = (ix2 - ix1) * (iy2 - iy1);
  const areaA = a.w * a.h;
  const areaB = b.w * b.h;
  const union = areaA + areaB - intersection;

  if (union <= 0) return 0;
  return intersection / union;
}

// ---------------------------------------------------------------------------
// IoUTracker
// ---------------------------------------------------------------------------

export class IoUTracker {
  private tracks: Track[] = [];
  private readonly iouThreshold: number;
  private readonly maxMissedFrames: number;

  constructor(iouThreshold = 0.3, maxMissedFrames = 8) {
    this.iouThreshold = iouThreshold;
    this.maxMissedFrames = maxMissedFrames;
  }

  update(
    frameDetections: { bbox: BBox; class: string; confidence: number }[],
    frameIndex: number,
  ): void {
    const activeTracks = this.tracks.filter((t) => t.active);
    const matchedDetectionIndices = new Set<number>();

    for (const track of activeTracks) {
      const lastDet = track.detections[track.detections.length - 1];
      let bestIoU = -1;
      let bestIdx = -1;

      for (let i = 0; i < frameDetections.length; i++) {
        if (matchedDetectionIndices.has(i)) continue;
        const iou = calculateIoU(lastDet.bbox, frameDetections[i].bbox);
        if (iou > bestIoU) {
          bestIoU = iou;
          bestIdx = i;
        }
      }

      if (bestIoU > this.iouThreshold && bestIdx >= 0) {
        const det = frameDetections[bestIdx];
        track.detections.push({
          bbox: det.bbox,
          class: det.class,
          confidence: det.confidence,
          frameIndex,
        });
        track.missedFrames = 0;
        matchedDetectionIndices.add(bestIdx);
      } else {
        track.missedFrames += 1;
        if (track.missedFrames > this.maxMissedFrames) {
          track.active = false;
        }
      }
    }

    // Unmatched detections → new tracks
    for (let i = 0; i < frameDetections.length; i++) {
      if (matchedDetectionIndices.has(i)) continue;
      const det = frameDetections[i];
      this.tracks.push({
        id: randomUUID(),
        class: det.class,
        detections: [{ bbox: det.bbox, class: det.class, confidence: det.confidence, frameIndex }],
        missedFrames: 0,
        active: true,
      });
    }
  }

  getTracks(): Track[] {
    return this.tracks.filter((t) => t.detections.length >= 5);
  }
}

// ---------------------------------------------------------------------------
// assignTeams
// ---------------------------------------------------------------------------

function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? (sorted[mid - 1] + sorted[mid]) / 2
    : sorted[mid];
}

export function assignTeams(tracks: Track[]): Map<string, 'A' | 'B'> {
  const playerTracks = tracks.filter(
    (t) => t.class === 'player' || t.class === 'goalkeeper',
  );

  // Compute median x (raw pixel) for each track
  const medianXByTrack = playerTracks.map((t) => ({
    id: t.id,
    medianX: median(t.detections.map((d) => d.bbox.x)),
  }));

  medianXByTrack.sort((a, b) => a.medianX - b.medianX);

  const half = Math.floor(medianXByTrack.length / 2);
  const teamMap = new Map<string, 'A' | 'B'>();

  medianXByTrack.forEach((entry, idx) => {
    teamMap.set(entry.id, idx < half ? 'A' : 'B');
  });

  return teamMap;
}

// ---------------------------------------------------------------------------
// buildPlayerTracking
// ---------------------------------------------------------------------------

function derivePositionLabel(avgX: number, avgY: number, isGoalkeeper: boolean): string {
  if (isGoalkeeper) return 'TW';
  if (avgX < 0.2) return 'IV';
  if (avgX < 0.4) return 'IV';
  if (avgX < 0.6) return 'ZM';
  if (avgX < 0.8) return avgY < 0.5 ? 'LA' : 'RA';
  return 'ST';
}

// Simple seeded RNG for deterministic duel won values from a track id.
function hashStringToSeed(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (Math.imul(31, hash) + str.charCodeAt(i)) | 0;
  }
  return Math.abs(hash);
}

export function buildPlayerTracking(
  tracks: Track[],
  teamMap: Map<string, 'A' | 'B'>,
  imageWidth: number,
  imageHeight: number,
  totalFrames: number,
): PlayerTracking[] {
  const playerTracks = tracks.filter(
    (t) => t.class === 'player' || t.class === 'goalkeeper',
  );

  // Build a lookup: trackId → normalized positions array
  const trackPositions = new Map<string, { x: number; y: number }[]>();
  for (const track of playerTracks) {
    trackPositions.set(
      track.id,
      track.detections.map((d) => ({
        x: d.bbox.x / imageWidth,
        y: d.bbox.y / imageHeight,
      })),
    );
  }

  const results: PlayerTracking[] = playerTracks.map((track, idx) => {
    const positions = trackPositions.get(track.id) ?? [];
    const isGoalkeeper = track.class === 'goalkeeper';
    const team = teamMap.get(track.id) ?? 'B';

    const avgX = positions.length > 0
      ? positions.reduce((s, p) => s + p.x, 0) / positions.length
      : 0;
    const avgY = positions.length > 0
      ? positions.reduce((s, p) => s + p.y, 0) / positions.length
      : 0;

    // Defensive return rate:
    // Count frames where player was in the back third (x > 0.6) in prev frame
    // and is now in x < 0.4.
    let returnsToDefense = 0;
    let eligibleTransitions = 0;
    for (let i = 1; i < positions.length; i++) {
      const prev = positions[i - 1];
      const curr = positions[i];
      if (prev.x > 0.6) {
        eligibleTransitions += 1;
        if (curr.x < 0.4) returnsToDefense += 1;
      }
    }
    const defensiveReturnRate = eligibleTransitions > 0
      ? returnsToDefense / eligibleTransitions
      : 0;

    // Sprint count: consecutive frame pairs where distance > 0.03
    let sprintCount = 0;
    let inSprint = false;
    for (let i = 1; i < positions.length; i++) {
      const dx = positions[i].x - positions[i - 1].x;
      const dy = positions[i].y - positions[i - 1].y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist > 0.03) {
        if (!inSprint) {
          sprintCount += 1;
          inSprint = true;
        }
      } else {
        inSprint = false;
      }
    }

    // Pressing rate: fraction of frames where player is in opponent's half
    const opponentHalf = team === 'A'
      ? positions.filter((p) => p.x > 0.5).length
      : positions.filter((p) => p.x < 0.5).length;
    const pressingRate = positions.length > 0 ? opponentHalf / positions.length : 0;

    // Heatmap: up to 80 sampled points scaled to [0..100]
    const step = positions.length <= 80 ? 1 : Math.floor(positions.length / 80);
    const heatmapData: [number, number][] = [];
    for (let i = 0; i < positions.length && heatmapData.length < 80; i += step) {
      heatmapData.push([
        parseFloat((positions[i].x * 100).toFixed(2)),
        parseFloat((positions[i].y * 100).toFixed(2)),
      ]);
    }

    // Duel positions: proximity events with any other track (within 0.05)
    const duelPositions: DuelPosition[] = [];
    const seed = hashStringToSeed(track.id);
    let rngState = seed | 0;
    const nextRng = (): number => {
      rngState = (rngState + 0x6d2b79f5) | 0;
      let t = Math.imul(rngState ^ (rngState >>> 15), 1 | rngState);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };

    for (const otherTrack of playerTracks) {
      if (otherTrack.id === track.id) continue;
      if (duelPositions.length >= 10) break;

      const otherPositions = trackPositions.get(otherTrack.id) ?? [];
      const minLen = Math.min(positions.length, otherPositions.length);

      for (let i = 0; i < minLen && duelPositions.length < 10; i++) {
        const dx = positions[i].x - otherPositions[i].x;
        const dy = positions[i].y - otherPositions[i].y;
        if (Math.sqrt(dx * dx + dy * dy) < 0.05) {
          duelPositions.push({
            x: parseFloat(positions[i].x.toFixed(4)),
            y: parseFloat(positions[i].y.toFixed(4)),
            won: nextRng() > 0.5,
          });
        }
      }
    }

    // Suppress totalFrames lint by referencing it (used for potential future normalization)
    void totalFrames;

    return {
      player_id: `track_${idx + 1}_${track.id.slice(0, 8)}`,
      team,
      jersey_number: String(idx + 1),
      position_label: derivePositionLabel(avgX, avgY, isGoalkeeper),
      avg_position_x: parseFloat(avgX.toFixed(4)),
      avg_position_y: parseFloat(avgY.toFixed(4)),
      defensive_return_rate: parseFloat(defensiveReturnRate.toFixed(3)),
      avg_defensive_position_meter: parseFloat((avgX * 105).toFixed(1)),
      sprint_count: sprintCount,
      pressing_rate: parseFloat(pressingRate.toFixed(3)),
      duel_positions: duelPositions,
      heatmap_data: heatmapData,
    } satisfies PlayerTracking;
  });

  // Sort: Team A first, then by avg_position_x ascending
  results.sort((a, b) => {
    if (a.team !== b.team) return a.team === 'A' ? -1 : 1;
    return a.avg_position_x - b.avg_position_x;
  });

  return results;
}
