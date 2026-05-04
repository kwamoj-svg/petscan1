import {
  VideoAnalysisResult,
  VideoPipelineType,
  PlayerTracking,
  DuelPosition,
} from '@/types/analysis';
import { errorResponse, AnalysisError } from '@/lib/errors';
import { MAX_VIDEO_SIZE_MB } from '@/lib/constants';

/**
 * Seeded pseudo-random number generator (Mulberry32).
 * Produces deterministic results for a given seed.
 */
function createSeededRandom(seed: number) {
  let s = seed | 0;
  return function (): number {
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Helper to generate a random float in [min, max] using the seeded RNG.
 */
function randRange(rng: () => number, min: number, max: number): number {
  return min + rng() * (max - min);
}

/**
 * Helper to generate a random integer in [min, max] using the seeded RNG.
 */
function randInt(rng: () => number, min: number, max: number): number {
  return Math.floor(randRange(rng, min, max + 1));
}

// Typical 4-3-3 positions (x, y) on a 0-1 pitch scale for the opponent team
const POSITION_TEMPLATES: { label: string; x: number; y: number }[] = [
  { label: 'TW', x: 0.05, y: 0.5 },
  { label: 'LV', x: 0.25, y: 0.15 },
  { label: 'IV', x: 0.2, y: 0.38 },
  { label: 'IV', x: 0.2, y: 0.62 },
  { label: 'RV', x: 0.25, y: 0.85 },
  { label: 'ZM', x: 0.45, y: 0.3 },
  { label: 'ZM', x: 0.4, y: 0.5 },
  { label: 'ZM', x: 0.45, y: 0.7 },
  { label: 'LA', x: 0.7, y: 0.15 },
  { label: 'ST', x: 0.75, y: 0.5 },
  { label: 'RA', x: 0.7, y: 0.85 },
];

function generateSimulatedPlayers(rng: () => number): PlayerTracking[] {
  return POSITION_TEMPLATES.map((template, index) => {
    const jerseyNumber = String(index + 1);

    // Add slight randomness to base position
    const avgX = Math.max(0, Math.min(1, template.x + randRange(rng, -0.05, 0.05)));
    const avgY = Math.max(0, Math.min(1, template.y + randRange(rng, -0.05, 0.05)));

    // Realistic defensive return rate: 0.2 - 0.8
    const defensiveReturnRate = randRange(rng, 0.2, 0.8);

    // Defensive position in meters (GK low, attackers high)
    const avgDefensivePositionMeter = randRange(rng, 15 + index * 5, 25 + index * 5);

    // Sprint count: 5 - 20
    const sprintCount = randInt(rng, 5, 20);

    // Pressing rate: 0.1 - 0.5
    const pressingRate = randRange(rng, 0.1, 0.5);

    // Generate 50-100 heatmap points clustered around average position
    const heatmapCount = randInt(rng, 50, 100);
    const heatmapData: [number, number][] = [];
    for (let i = 0; i < heatmapCount; i++) {
      const hx = Math.max(0, Math.min(1, avgX + randRange(rng, -0.15, 0.15)));
      const hy = Math.max(0, Math.min(1, avgY + randRange(rng, -0.12, 0.12)));
      heatmapData.push([hx, hy]);
    }

    // Generate 5-15 duel positions
    const duelCount = randInt(rng, 5, 15);
    const duelPositions: DuelPosition[] = [];
    for (let i = 0; i < duelCount; i++) {
      duelPositions.push({
        x: Math.max(0, Math.min(1, avgX + randRange(rng, -0.2, 0.2))),
        y: Math.max(0, Math.min(1, avgY + randRange(rng, -0.15, 0.15))),
        won: rng() > 0.45, // ~55% duel success rate
      });
    }

    return {
      player_id: `opponent_${jerseyNumber}`,
      team: 'B' as const,
      jersey_number: jerseyNumber,
      position_label: template.label,
      avg_position_x: parseFloat(avgX.toFixed(4)),
      avg_position_y: parseFloat(avgY.toFixed(4)),
      defensive_return_rate: parseFloat(defensiveReturnRate.toFixed(3)),
      avg_defensive_position_meter: parseFloat(avgDefensivePositionMeter.toFixed(1)),
      sprint_count: sprintCount,
      pressing_rate: parseFloat(pressingRate.toFixed(3)),
      duel_positions: duelPositions,
      heatmap_data: heatmapData,
    };
  });
}

export async function POST(request: Request) {
  try {
    const formData = await request.formData();
    const videoFile = formData.get('video') as File | null;

    if (!videoFile) {
      throw new AnalysisError('Keine Videodatei hochgeladen.', 400);
    }

    const fileSizeMB = videoFile.size / (1024 * 1024);
    if (fileSizeMB > MAX_VIDEO_SIZE_MB) {
      throw new AnalysisError(
        `Video ist zu groß (${fileSizeMB.toFixed(1)} MB). Maximum: ${MAX_VIDEO_SIZE_MB} MB.`,
        400
      );
    }

    // TODO: Real implementation would extract video metadata using FFmpeg here:
    //   const metadata = await ffmpeg.probe(videoBuffer);
    //   const duration = metadata.format.duration;
    //   const resolution = { width: metadata.streams[0].width, height: metadata.streams[0].height };

    // Determine pipeline type based on video metadata.
    // TODO: Real implementation would analyze camera movement patterns:
    //   - fixed_camera: Single static camera angle, consistent perspective
    //   - broadcast: Multiple camera angles with cuts, overlays, replays
    // For now, use file name or default to broadcast.
    const fileName = videoFile.name.toLowerCase();
    const pipelineType: VideoPipelineType = fileName.includes('fixed')
      ? 'fixed_camera'
      : 'broadcast';

    // TODO: Real implementation pipeline:
    //   1. FFmpeg: Extract frames at configured FPS (e.g., 2fps for broadcast, 5fps for fixed)
    //   2. Roboflow: Run player detection model on each frame
    //      - Detect bounding boxes for all players
    //      - Classify team membership (jersey color clustering)
    //   3. ByteTrack: Multi-object tracking across frames
    //      - Assign consistent player IDs
    //      - Track position trajectories
    //   4. Homography: Map pixel coordinates to pitch coordinates (0-1 scale)
    //   5. Analytics: Calculate per-player metrics from tracking data
    //      - Defensive return rate from position changes after possession loss
    //      - Sprint detection from velocity thresholds
    //      - Pressing rate from forward movement patterns
    //      - Heatmap from position frequency
    //      - Duel detection from proximity events

    // SIMULATION: Use file size as seed for deterministic results
    const seed = videoFile.size;
    const rng = createSeededRandom(seed);

    const players = generateSimulatedPlayers(rng);

    // Simulate realistic video metrics
    const videoDurationSeconds = randRange(rng, 45 * 60, 95 * 60); // 45-95 minutes
    const fps = pipelineType === 'fixed_camera' ? 5 : 2;
    const totalFramesAnalyzed = Math.floor(videoDurationSeconds * fps);

    const result: VideoAnalysisResult = {
      pipeline_type: pipelineType,
      players,
      total_frames_analyzed: totalFramesAnalyzed,
      video_duration_seconds: parseFloat(videoDurationSeconds.toFixed(1)),
    };

    return Response.json(result);
  } catch (error) {
    return errorResponse(error);
  }
}
