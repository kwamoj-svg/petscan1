import ffmpegStatic from 'ffmpeg-static';
import { execFile } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';

const execFileAsync = promisify(execFile);

export interface VideoInfo {
  duration: number;        // seconds
  width: number;
  height: number;
  fps: number;
  isLikelyBroadcast: boolean;  // true if many scene cuts detected
}

function getFfmpegPath(): string {
  if (!ffmpegStatic) {
    throw new Error('FFmpeg nicht verfügbar');
  }
  return ffmpegStatic;
}

export async function getVideoInfo(videoPath: string): Promise<VideoInfo> {
  const ffmpeg = getFfmpegPath();

  let stderr = '';
  try {
    await execFileAsync(ffmpeg, ['-i', videoPath, '-f', 'null', '-'], {
      maxBuffer: 10 * 1024 * 1024,
    });
  } catch (err: unknown) {
    // ffmpeg always exits with code 1 for -f null - so we expect an error
    if (err && typeof err === 'object' && 'stderr' in err) {
      stderr = (err as { stderr: string }).stderr;
    } else {
      throw err;
    }
  }

  // Parse duration
  const durationMatch = stderr.match(/Duration: (\d+):(\d+):(\d+\.?\d*)/);
  let duration = 0;
  if (durationMatch) {
    const hours = parseInt(durationMatch[1], 10);
    const minutes = parseInt(durationMatch[2], 10);
    const seconds = parseFloat(durationMatch[3]);
    duration = hours * 3600 + minutes * 60 + seconds;
  }

  // Parse FPS
  const fpsMatch = stderr.match(/(\d+(?:\.\d+)?) fps/);
  const fps = fpsMatch ? parseFloat(fpsMatch[1]) : 25;

  // Parse resolution
  const sizeMatch = stderr.match(/(\d+)x(\d+)/);
  const width = sizeMatch ? parseInt(sizeMatch[1], 10) : 0;
  const height = sizeMatch ? parseInt(sizeMatch[2], 10) : 0;

  // Determine isLikelyBroadcast heuristically
  let isLikelyBroadcast: boolean;
  if (duration < 60) {
    isLikelyBroadcast = false;
  } else if (duration > 300 && fps >= 24) {
    isLikelyBroadcast = true;
  } else {
    isLikelyBroadcast = false;
  }

  return { duration, width, height, fps, isLikelyBroadcast };
}

export async function extractFrames(
  videoPath: string,
  outputDir: string,
  fps: number,
  maxFrames?: number,
): Promise<string[]> {
  const ffmpeg = getFfmpegPath();

  const info = await getVideoInfo(videoPath);
  const frameLimit = maxFrames ?? (info.isLikelyBroadcast ? 90 : 150);

  const vfFilter = `fps=${fps},scale=640:640:force_original_aspect_ratio=decrease,pad=640:640:(ow-iw)/2:(oh-ih)/2`;
  const outputPattern = path.join(outputDir, 'frame_%04d.jpg');

  await execFileAsync(ffmpeg, [
    '-i', videoPath,
    '-vf', vfFilter,
    '-frames:v', String(frameLimit),
    '-q:v', '5',
    outputPattern,
  ], {
    maxBuffer: 50 * 1024 * 1024,
  });

  const files = fs
    .readdirSync(outputDir)
    .filter((f) => f.startsWith('frame_') && f.endsWith('.jpg'))
    .sort()
    .map((f) => path.resolve(outputDir, f));

  return files;
}

export function createTempDir(): string {
  const uuid = crypto.randomUUID();
  const dir = path.join(os.tmpdir(), `gegneranalyse-${uuid}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

export function cleanup(dir: string): void {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    // ignore errors
  }
}
