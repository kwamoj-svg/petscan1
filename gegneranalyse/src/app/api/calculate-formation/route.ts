import { PlayerTracking, FormationData } from '@/types/analysis';
import { errorResponse, AnalysisError } from '@/lib/errors';

/**
 * Find the largest gaps in sorted x-positions to split players into formation lines.
 * Returns indices where splits should occur.
 */
function findLineBreaks(
  sortedPositions: number[],
  numBreaks: number
): number[] {
  if (sortedPositions.length <= 1) return [];

  const gaps: { index: number; gap: number }[] = [];
  for (let i = 1; i < sortedPositions.length; i++) {
    gaps.push({ index: i, gap: sortedPositions[i] - sortedPositions[i - 1] });
  }

  gaps.sort((a, b) => b.gap - a.gap);

  const breakIndices = gaps
    .slice(0, Math.min(numBreaks, gaps.length))
    .map((g) => g.index)
    .sort((a, b) => a - b);

  return breakIndices;
}

/**
 * Given sorted x-positions of outfield players, determine formation string (e.g. "4-3-3").
 */
function detectFormation(sortedXPositions: number[]): string {
  const count = sortedXPositions.length;
  if (count === 0) return '0';

  // Determine number of line breaks: aim for 3 lines (defense-midfield-attack)
  // but use 2 if fewer than 7 players
  const numBreaks = count >= 7 ? 3 : count >= 4 ? 2 : 1;

  const breaks = findLineBreaks(sortedXPositions, numBreaks);

  const lines: number[] = [];
  let start = 0;
  for (const brk of breaks) {
    lines.push(brk - start);
    start = brk;
  }
  lines.push(count - start);

  return lines.join('-');
}

/**
 * Split players into first-half and second-half based on heatmap frame indices.
 */
function splitByHalf(players: PlayerTracking[]): {
  firstHalf: PlayerTracking[];
  secondHalf: PlayerTracking[];
} {
  const firstHalf: PlayerTracking[] = [];
  const secondHalf: PlayerTracking[] = [];

  for (const player of players) {
    if (player.heatmap_data && player.heatmap_data.length > 0) {
      const totalFrames = player.heatmap_data.length;
      const midpoint = Math.floor(totalFrames / 2);

      const firstHalfData = player.heatmap_data.slice(0, midpoint);
      const secondHalfData = player.heatmap_data.slice(midpoint);

      const avgXFirst =
        firstHalfData.length > 0
          ? firstHalfData.reduce((sum, [x]) => sum + x, 0) / firstHalfData.length
          : player.avg_position_x;

      const avgXSecond =
        secondHalfData.length > 0
          ? secondHalfData.reduce((sum, [x]) => sum + x, 0) / secondHalfData.length
          : player.avg_position_x;

      firstHalf.push({ ...player, avg_position_x: avgXFirst });
      secondHalf.push({ ...player, avg_position_x: avgXSecond });
    } else {
      // No heatmap data: use same position for both halves
      firstHalf.push({ ...player });
      secondHalf.push({ ...player });
    }
  }

  return { firstHalf, secondHalf };
}

function getOutfieldPlayers(players: PlayerTracking[]): PlayerTracking[] {
  // Filter team B (opponent)
  const teamB = players.filter((p) => p.team === 'B');

  if (teamB.length === 0) return [];

  // Exclude goalkeeper: player with lowest avg_position_x (typically < 0.1)
  const sorted = [...teamB].sort((a, b) => a.avg_position_x - b.avg_position_x);
  const gkCandidate = sorted[0];

  if (gkCandidate.avg_position_x < 0.1) {
    return sorted.slice(1);
  }

  // If no obvious GK, still remove the deepest player
  return sorted.slice(1);
}

function formationFromPlayers(players: PlayerTracking[]): string {
  const sorted = [...players].sort(
    (a, b) => a.avg_position_x - b.avg_position_x
  );
  const xPositions = sorted.map((p) => p.avg_position_x);
  return detectFormation(xPositions);
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { players } = body as { players: PlayerTracking[] };

    if (!players || !Array.isArray(players) || players.length === 0) {
      throw new AnalysisError(
        'Spielerdaten müssen als Array angegeben werden.',
        400
      );
    }

    const outfield = getOutfieldPlayers(players);

    if (outfield.length === 0) {
      throw new AnalysisError(
        'Keine Feldspieler des Gegners gefunden.',
        400
      );
    }

    // Main formation (all players, all time)
    const mainFormation = formationFromPlayers(outfield);

    // With ball / without ball based on pressing_rate
    // High pressing_rate => "with ball" posture (aggressive), low => "without ball" (defensive)
    const withBallPlayers = outfield.filter((p) => p.pressing_rate >= 0.5);
    const withoutBallPlayers = outfield.filter((p) => p.pressing_rate < 0.5);

    const formationWithBall =
      withBallPlayers.length >= 3
        ? formationFromPlayers(withBallPlayers)
        : mainFormation;

    const formationWithoutBall =
      withoutBallPlayers.length >= 3
        ? formationFromPlayers(withoutBallPlayers)
        : mainFormation;

    // First half vs second half
    const { firstHalf, secondHalf } = splitByHalf(outfield);

    const formationFirstHalf = formationFromPlayers(firstHalf);
    const formationSecondHalf = formationFromPlayers(secondHalf);

    // Detect formation change
    const changedFormation = formationFirstHalf !== formationSecondHalf;

    const result: FormationData = {
      formation_with_ball: formationWithBall,
      formation_without_ball: formationWithoutBall,
      formation_first_half: formationFirstHalf,
      formation_second_half: formationSecondHalf,
      changed_formation: changedFormation,
      formation_change_minute: changedFormation ? 45 : null,
    };

    return Response.json(result);
  } catch (error) {
    return errorResponse(error);
  }
}
