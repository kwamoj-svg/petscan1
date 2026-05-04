import { VideoAnalysisResult, VideoPipelineType, PlayerTracking, DuelPosition } from '@/types/analysis';
import { errorResponse, AnalysisError } from '@/lib/errors';
import { MAX_VIDEO_SIZE_MB } from '@/lib/constants';
import { getVideoInfo, extractFrames, createTempDir, cleanup } from '@/lib/videoUtils';
import { detectPlayersInFrame } from '@/lib/roboflowClient';
import { IoUTracker, assignTeams, buildPlayerTracking } from '@/lib/playerTracker';
import * as fs from 'fs';
import * as path from 'path';

export const runtime = 'nodejs';
export const maxDuration = 300;

// ---------------------------------------------------------------------------
// Seeded simulation fallback
// ---------------------------------------------------------------------------

function createSeededRandom(seed: number) {
  let s = seed | 0;
  return function (): number {
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randRange(rng: () => number, min: number, max: number): number {
  return min + rng() * (max - min);
}

function randInt(rng: () => number, min: number, max: number): number {
  return Math.floor(randRange(rng, min, max + 1));
}

const POSITION_TEMPLATES: { label: string; x: number; y: number }[] = [
  { label: 'TW', x: 0.05, y: 0.5 },
  { label: 'LV', x: 0.25, y: 0.15 },
  { label: 'IV', x: 0.2,  y: 0.38 },
  { label: 'IV', x: 0.2,  y: 0.62 },
  { label: 'RV', x: 0.25, y: 0.85 },
  { label: 'ZM', x: 0.45, y: 0.3 },
  { label: 'ZM', x: 0.4,  y: 0.5 },
  { label: 'ZM', x: 0.45, y: 0.7 },
  { label: 'LA', x: 0.7,  y: 0.15 },
  { label: 'ST', x: 0.75, y: 0.5 },
  { label: 'RA', x: 0.7,  y: 0.85 },
];

function simulatePlayers(seed: number): PlayerTracking[] {
  const rng = createSeededRandom(seed);

  return POSITION_TEMPLATES.map((template, index) => {
    const jerseyNumber = String(index + 1);

    const avgX = Math.max(0, Math.min(1, template.x + randRange(rng, -0.05, 0.05)));
    const avgY = Math.max(0, Math.min(1, template.y + randRange(rng, -0.05, 0.05)));

    const defensiveReturnRate = randRange(rng, 0.2, 0.8);
    const avgDefensivePositionMeter = randRange(rng, 15 + index * 5, 25 + index * 5);
    const sprintCount = randInt(rng, 5, 20);
    const pressingRate = randRange(rng, 0.1, 0.5);

    const heatmapCount = randInt(rng, 50, 100);
    const heatmapData: [number, number][] = [];
    for (let i = 0; i < heatmapCount; i++) {
      const hx = Math.max(0, Math.min(1, avgX + randRange(rng, -0.15, 0.15)));
      const hy = Math.max(0, Math.min(1, avgY + randRange(rng, -0.12, 0.12)));
      heatmapData.push([hx, hy]);
    }

    const duelCount = randInt(rng, 5, 15);
    const duelPositions: DuelPosition[] = [];
    for (let i = 0; i < duelCount; i++) {
      duelPositions.push({
        x: Math.max(0, Math.min(1, avgX + randRange(rng, -0.2, 0.2))),
        y: Math.max(0, Math.min(1, avgY + randRange(rng, -0.15, 0.15))),
        won: rng() > 0.45,
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

// ---------------------------------------------------------------------------
// POST handler
// ---------------------------------------------------------------------------

export async function POST(request: Request) {
  let tempDir: string | null = null;

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
        400,
      );
    }

    // --- Fallback to simulation if Roboflow credentials are missing ---
    const apiKey = process.env.ROBOFLOW_API_KEY;
    const modelId = process.env.ROBOFLOW_MODEL_ID;

    if (!apiKey || !modelId) {
      console.warn('analyze-video: ROBOFLOW_API_KEY or ROBOFLOW_MODEL_ID not set — using simulation fallback.');

      const seed = videoFile.size;
      const players = simulatePlayers(seed);

      const rng = createSeededRandom(seed + 1);
      const videoDurationSeconds = randRange(rng, 45 * 60, 95 * 60);
      const fileName = videoFile.name.toLowerCase();
      const pipelineType: VideoPipelineType = fileName.includes('fixed') ? 'fixed_camera' : 'broadcast';
      const fps = pipelineType === 'fixed_camera' ? 2 : 1;
      const totalFramesAnalyzed = Math.floor(videoDurationSeconds * fps);

      const result: VideoAnalysisResult = {
        pipeline_type: pipelineType,
        players,
        total_frames_analyzed: totalFramesAnalyzed,
        video_duration_seconds: parseFloat(videoDurationSeconds.toFixed(1)),
      };
      return Response.json(result);
    }

    // --- Real pipeline ---
    tempDir = createTempDir();
    const videoPath = path.join(tempDir, 'video.mp4');
    const framesDir = path.join(tempDir, 'frames');
    fs.mkdirSync(framesDir, { recursive: true });

    // Write video buffer to disk
    const videoBuffer = Buffer.from(await videoFile.arrayBuffer());
    fs.writeFileSync(videoPath, videoBuffer);

    // Probe video metadata
    const videoInfo = await getVideoInfo(videoPath);

    // Determine pipeline type and extraction FPS
    const pipelineType: VideoPipelineType = videoInfo.isLikelyBroadcast ? 'broadcast' : 'fixed_camera';
    const extractFps = pipelineType === 'fixed_camera' ? 2 : 1;

    // Extract frames (cap at 90)
    const frames = await extractFrames(videoPath, framesDir, extractFps, 90);

    // Run IoU tracker over all frames sequentially
    const tracker = new IoUTracker();

    for (let frameIndex = 0; frameIndex < frames.length; frameIndex++) {
      const framePath = frames[frameIndex];

      const rawDetections = await detectPlayersInFrame(framePath, modelId, apiKey);

      const detections = rawDetections.map((det) => ({
        bbox: { x: det.x, y: det.y, w: det.width, h: det.height },
        class: det.class,
        confidence: det.confidence,
      }));

      tracker.update(detections, frameIndex);

      // Delete frame immediately to free disk space
      try {
        fs.unlinkSync(framePath);
      } catch {
        // non-fatal — temp dir will be cleaned up anyway
      }
    }

    // Build player tracking data
    const tracks = tracker.getTracks();
    const teamMap = assignTeams(tracks);
    const players = buildPlayerTracking(tracks, teamMap, 640, 640, frames.length);

    cleanup(tempDir);
    tempDir = null;

    const result: VideoAnalysisResult = {
      pipeline_type: pipelineType,
      players,
      total_frames_analyzed: frames.length,
      video_duration_seconds: parseFloat(videoInfo.duration.toFixed(1)),
    };

    return Response.json(result);
  } catch (error) {
    if (tempDir) {
      cleanup(tempDir);
    }
    return errorResponse(error);
  }
}
