import {
  PlayerTracking,
  FormationData,
  TeamWeaknesses,
  PlayerWeakness,
  DefensiveRating,
  PressingLabel,
  DefensiveLineLabel,
} from '@/types/analysis';
import {
  DEFENSIVE_RETURN_THRESHOLDS,
  PRESSING_POSITION_THRESHOLD,
  OPPONENT_DISTANCE_THRESHOLD,
  DEFENSIVE_LINE_THRESHOLDS,
} from '@/lib/constants';
import { errorResponse, AnalysisError } from '@/lib/errors';

function getDefensiveRating(rate: number): DefensiveRating {
  if (rate < DEFENSIVE_RETURN_THRESHOLDS.weak) return 'Defensiv schwach';
  if (rate <= DEFENSIVE_RETURN_THRESHOLDS.strong) return 'Defensiv mittel';
  return 'Defensiv stark';
}

function getPressingLabel(avgPosition: number): PressingLabel {
  if (avgPosition > PRESSING_POSITION_THRESHOLD) return 'Kein Pressing';
  if (avgPosition > 40) return 'Mittleres Pressing';
  return 'Hohes Pressing';
}

function getDefensiveLineLabel(height: number): DefensiveLineLabel {
  if (height < DEFENSIVE_LINE_THRESHOLDS.low) return 'Tiefe Abwehr';
  if (height <= DEFENSIVE_LINE_THRESHOLDS.high) return 'Mittlere Abwehrlinie';
  return 'Hohe Abwehrlinie';
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { players, formation } = body as {
      players: PlayerTracking[];
      formation: FormationData;
    };

    if (!players || !Array.isArray(players) || players.length === 0) {
      throw new AnalysisError(
        'Spielerdaten müssen als Array angegeben werden.',
        400
      );
    }

    if (!formation) {
      throw new AnalysisError(
        'Formationsdaten müssen angegeben werden.',
        400
      );
    }

    // Filter to opponent team (B), exclude GK
    const teamB = players.filter((p) => p.team === 'B');
    const sorted = [...teamB].sort(
      (a, b) => a.avg_position_x - b.avg_position_x
    );
    const outfield =
      sorted.length > 0 && sorted[0].avg_position_x < 0.1
        ? sorted.slice(1)
        : sorted.length > 0
          ? sorted.slice(1)
          : [];

    // Team-level: defensive line height (average of defensive players' positions in meters)
    // Use avg_defensive_position_meter for all outfield players
    const defensivePositions = outfield.map(
      (p) => p.avg_defensive_position_meter
    );
    const avgDefensiveLineMeter =
      defensivePositions.length > 0
        ? defensivePositions.reduce((sum, v) => sum + v, 0) /
          defensivePositions.length
        : 0;

    const defensiveLineLabel = getDefensiveLineLabel(avgDefensiveLineMeter);

    // Team-level: pressing label based on average pressing position
    // Use avg_defensive_position_meter as proxy for pressing height
    const avgPressingPosition =
      outfield.length > 0
        ? outfield.reduce((sum, p) => sum + p.avg_defensive_position_meter, 0) /
          outfield.length
        : 0;

    const pressingLabel = getPressingLabel(avgPressingPosition);

    // Per-player weaknesses
    const playerWeaknesses: PlayerWeakness[] = outfield.map((player) => {
      const defensiveReturnLabel = getDefensiveRating(
        player.defensive_return_rate
      );

      // Estimate average distance to nearest opponent from duel positions
      // If duel data exists, use average distance; otherwise null
      let avgDistanceToOpponent: number | null = null;
      if (player.duel_positions && player.duel_positions.length > 0) {
        // Use the spread of duel positions as a proxy for opponent distance
        const avgDuelX =
          player.duel_positions.reduce((s, d) => s + d.x, 0) /
          player.duel_positions.length;
        const avgDuelY =
          player.duel_positions.reduce((s, d) => s + d.y, 0) /
          player.duel_positions.length;
        // Distance from player's average position to average duel position (in field units)
        avgDistanceToOpponent = Math.sqrt(
          Math.pow(player.avg_position_x - avgDuelX, 2) +
            Math.pow(player.avg_position_y - avgDuelY, 2)
        ) * 100; // Convert normalized to meters approximation
      }

      const leavesOpponentFree =
        avgDistanceToOpponent !== null
          ? avgDistanceToOpponent > OPPONENT_DISTANCE_THRESHOLD
          : false;

      return {
        player_id: player.player_id,
        jersey_number: player.jersey_number,
        position: player.position_label,
        defensive_return_label: defensiveReturnLabel,
        defensive_return_rate: player.defensive_return_rate,
        leaves_opponent_free: leavesOpponentFree,
        avg_distance_to_opponent: avgDistanceToOpponent,
      };
    });

    const result: TeamWeaknesses = {
      defensive_line_height: defensiveLineLabel,
      defensive_line_meters: Math.round(avgDefensiveLineMeter * 10) / 10,
      pressing_label: pressingLabel,
      avg_pressing_position: Math.round(avgPressingPosition * 10) / 10,
      player_weaknesses: playerWeaknesses,
    };

    return Response.json(result);
  } catch (error) {
    return errorResponse(error);
  }
}
