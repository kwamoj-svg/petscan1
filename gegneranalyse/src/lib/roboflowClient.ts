import * as fs from 'fs';

export interface RoboflowDetection {
  x: number;           // center x in pixels
  y: number;           // center y in pixels
  width: number;       // bounding box width
  height: number;      // bounding box height
  confidence: number;  // 0-1
  class: 'player' | 'goalkeeper' | 'ball' | 'referee';
  detection_id: string;
}

export interface RoboflowResponse {
  predictions: RoboflowDetection[];
  image: { width: number; height: number };
}

async function postToRoboflow(
  url: string,
  body: URLSearchParams,
): Promise<RoboflowResponse> {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: body.toString(),
  });

  if (!response.ok) {
    throw new Error(`Roboflow API error: ${response.status} ${response.statusText}`);
  }

  return response.json() as Promise<RoboflowResponse>;
}

export async function detectPlayersInFrame(
  imagePath: string,
  modelId: string,
  apiKey: string,
): Promise<RoboflowDetection[]> {
  let imageBuffer: Buffer;
  try {
    imageBuffer = fs.readFileSync(imagePath);
  } catch (err) {
    console.error('roboflowClient: failed to read image file:', imagePath, err);
    return [];
  }

  const base64Image = imageBuffer.toString('base64');
  const url = `https://detect.roboflow.com/${modelId}?api_key=${apiKey}&confidence=40&overlap=30`;
  const body = new URLSearchParams({ file: base64Image });

  try {
    const result = await postToRoboflow(url, body);
    return result.predictions ?? [];
  } catch (firstErr) {
    console.error('roboflowClient: first attempt failed, retrying in 1s...', firstErr);

    await new Promise<void>((resolve) => setTimeout(resolve, 1000));

    try {
      const result = await postToRoboflow(url, body);
      return result.predictions ?? [];
    } catch (secondErr) {
      console.error('roboflowClient: retry also failed:', secondErr);
      return [];
    }
  }
}
