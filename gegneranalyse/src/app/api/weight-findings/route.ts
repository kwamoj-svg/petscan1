import {
  StatsData,
  TeamWeaknesses,
  VideoAnalysisResult,
  FormationData,
  Pipeline,
  WeightedFinding,
  HybridWeightResult,
  Confidence,
  EvidenceSource,
} from '@/types/analysis';
import { errorResponse, AnalysisError } from '@/lib/errors';

function noEvidence(): EvidenceSource {
  return { available: false, value: '', source: '' };
}

function determineConfidence(
  stats: EvidenceSource,
  video: EvidenceSource
): { confidence: Confidence; reason: string } | null {
  if (stats.available && video.available) {
    // Simple heuristic: if both values contain numbers, compare them
    const statsNum = parseFloat(stats.value);
    const videoNum = parseFloat(video.value);
    if (!isNaN(statsNum) && !isNaN(videoNum)) {
      const diff = Math.abs(statsNum - videoNum);
      const avg = (Math.abs(statsNum) + Math.abs(videoNum)) / 2;
      if (avg > 0 && diff / avg > 0.5) {
        return { confidence: 'CONFLICT', reason: 'Stats und Video widersprechen sich deutlich.' };
      }
    }
    return { confidence: 'HIGH', reason: 'Durch Stats und Video bestätigt.' };
  }
  if (stats.available || video.available) {
    return {
      confidence: 'MEDIUM',
      reason: stats.available
        ? 'Nur durch Stats belegt.'
        : 'Nur durch Video belegt.',
    };
  }
  // Neither available -> skip
  return null;
}

function buildSideWeaknessFinding(
  side: 'left' | 'right',
  stats_data: StatsData | undefined,
  video_result: VideoAnalysisResult | undefined
): WeightedFinding | null {
  const label = side === 'left' ? 'linke' : 'rechte';
  const finding = `Schwachstelle ${label} Seite`;

  const stats: EvidenceSource = stats_data
    ? {
        available: true,
        value: `${stats_data.conceded_by_side[side]}% Gegentore über ${label} Seite`,
        source: 'conceded_by_side stats',
      }
    : noEvidence();

  // Look at defenders on that side from video
  let video: EvidenceSource = noEvidence();
  if (video_result) {
    const sidePlayers = video_result.players.filter((p) => {
      if (side === 'left') return p.avg_position_y < 0.35;
      return p.avg_position_y > 0.65;
    });
    if (sidePlayers.length > 0) {
      const avgReturn =
        sidePlayers.reduce((sum, p) => sum + p.defensive_return_rate, 0) /
        sidePlayers.length;
      video = {
        available: true,
        value: `Durchschnittliche Rücklaufquote ${label} Seite: ${(avgReturn * 100).toFixed(1)}%`,
        source: 'video player tracking',
      };
    }
  }

  const result = determineConfidence(stats, video);
  if (!result) return null;

  return { finding, stats_evidence: stats, video_evidence: video, ...result, confidence_reason: result.reason };
}

function buildPressingFinding(
  stats_data: StatsData | undefined,
  video_result: VideoAnalysisResult | undefined
): WeightedFinding | null {
  const finding = 'Pressing-Schwäche';

  const stats: EvidenceSource =
    stats_data?.ppda != null
      ? {
          available: true,
          value: `PPDA: ${stats_data.ppda.toFixed(1)}`,
          source: 'PPDA stats',
        }
      : noEvidence();

  let video: EvidenceSource = noEvidence();
  if (video_result && video_result.players.length > 0) {
    const avgPressing =
      video_result.players.reduce((sum, p) => sum + p.pressing_rate, 0) /
      video_result.players.length;
    video = {
      available: true,
      value: `Durchschnittliche Pressing-Rate: ${(avgPressing * 100).toFixed(1)}%`,
      source: 'video pressing analysis',
    };
  }

  const result = determineConfidence(stats, video);
  if (!result) return null;

  return { finding, stats_evidence: stats, video_evidence: video, ...result, confidence_reason: result.reason };
}

function buildSetPieceFinding(
  stats_data: StatsData | undefined
): WeightedFinding | null {
  const finding = 'Standardsituationen-Anfälligkeit';

  const stats: EvidenceSource = stats_data
    ? {
        available: true,
        value: `${stats_data.set_piece_goals_against} Gegentore nach Standards`,
        source: 'set piece stats',
      }
    : noEvidence();

  // Set pieces are typically only from stats
  const video: EvidenceSource = noEvidence();

  const result = determineConfidence(stats, video);
  if (!result) return null;

  return { finding, stats_evidence: stats, video_evidence: video, ...result, confidence_reason: result.reason };
}

function buildFormationChangeFinding(
  formation: FormationData,
  video_result: VideoAnalysisResult | undefined
): WeightedFinding | null {
  if (!formation.changed_formation) return null;

  const finding = 'Formationswechsel';

  const stats: EvidenceSource = {
    available: true,
    value: `Wechsel von ${formation.formation_first_half} auf ${formation.formation_second_half}${formation.formation_change_minute ? ` in Minute ${formation.formation_change_minute}` : ''}`,
    source: 'formation analysis',
  };

  const video: EvidenceSource = video_result
    ? {
        available: true,
        value: `Formationswechsel im Video erkannt`,
        source: 'video formation tracking',
      }
    : noEvidence();

  const result = determineConfidence(stats, video);
  if (!result) return null;

  return { finding, stats_evidence: stats, video_evidence: video, ...result, confidence_reason: result.reason };
}

function buildPlayerWeaknessFindings(
  weaknesses: TeamWeaknesses,
  video_result: VideoAnalysisResult | undefined
): WeightedFinding[] {
  const findings: WeightedFinding[] = [];

  for (const pw of weaknesses.player_weaknesses) {
    const finding = `Spieler #${pw.jersey_number} (${pw.position}): ${pw.defensive_return_label}`;

    const stats: EvidenceSource = {
      available: true,
      value: `Rücklaufquote: ${(pw.defensive_return_rate * 100).toFixed(1)}%, Lässt Gegner frei: ${pw.leaves_opponent_free ? 'Ja' : 'Nein'}`,
      source: 'weakness analysis',
    };

    let video: EvidenceSource = noEvidence();
    if (video_result) {
      const videoPlayer = video_result.players.find(
        (p) => p.jersey_number === pw.jersey_number
      );
      if (videoPlayer) {
        video = {
          available: true,
          value: `Video-Rücklaufquote: ${(videoPlayer.defensive_return_rate * 100).toFixed(1)}%, Sprints: ${videoPlayer.sprint_count}`,
          source: 'video player tracking',
        };
      }
    }

    const result = determineConfidence(stats, video);
    if (!result) continue;

    findings.push({
      finding,
      stats_evidence: stats,
      video_evidence: video,
      ...result,
      confidence_reason: result.reason,
    });
  }

  return findings;
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const {
      stats_data,
      weaknesses,
      video_result,
      formation,
      pipeline,
    } = body as {
      stats_data?: StatsData;
      weaknesses: TeamWeaknesses;
      video_result?: VideoAnalysisResult;
      formation: FormationData;
      pipeline: Pipeline;
    };

    if (!weaknesses || !formation || !pipeline) {
      throw new AnalysisError(
        'Weaknesses, Formation und Pipeline müssen angegeben werden.',
        400
      );
    }

    const findings: WeightedFinding[] = [];

    // 1. Side weaknesses
    const leftSide = buildSideWeaknessFinding('left', stats_data, video_result);
    if (leftSide) findings.push(leftSide);

    const rightSide = buildSideWeaknessFinding('right', stats_data, video_result);
    if (rightSide) findings.push(rightSide);

    // 2. Pressing weakness
    const pressing = buildPressingFinding(stats_data, video_result);
    if (pressing) findings.push(pressing);

    // 3. Set piece vulnerability
    const setPiece = buildSetPieceFinding(stats_data);
    if (setPiece) findings.push(setPiece);

    // 4. Formation change
    const formationChange = buildFormationChangeFinding(formation, video_result);
    if (formationChange) findings.push(formationChange);

    // 5. Per-player weaknesses
    const playerFindings = buildPlayerWeaknessFindings(weaknesses, video_result);
    findings.push(...playerFindings);

    const result: HybridWeightResult = { findings };

    return Response.json(result);
  } catch (error) {
    return errorResponse(error);
  }
}
