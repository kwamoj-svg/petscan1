import Anthropic from '@anthropic-ai/sdk';
import { DataAvailability, StatsData, GameResult, KeyPlayer, SideDistribution } from '@/types/analysis';
import { errorResponse, AnalysisError } from '@/lib/errors';

const anthropic = new Anthropic();

const statsToolSchema: Anthropic.Tool = {
  name: 'report_team_stats',
  description:
    'Report compiled statistics for a football team including recent results, formation, xG, goals distribution, and key players.',
  input_schema: {
    type: 'object' as const,
    properties: {
      last_8_games: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            date: { type: 'string', description: 'Match date in YYYY-MM-DD format' },
            opponent: { type: 'string' },
            score_for: { type: 'number' },
            score_against: { type: 'number' },
            home: { type: 'boolean' },
          },
          required: ['date', 'opponent', 'score_for', 'score_against', 'home'],
        },
        description: 'Last 8 game results',
      },
      preferred_formation: {
        type: 'string',
        description: 'Most used formation, e.g. "4-3-3"',
      },
      xg_for: {
        type: ['number', 'null'],
        description: 'Expected goals for (per game average), null if unavailable',
      },
      xg_against: {
        type: ['number', 'null'],
        description: 'Expected goals against (per game average), null if unavailable',
      },
      goals_by_side: {
        type: 'object',
        properties: {
          left: { type: 'number' },
          center: { type: 'number' },
          right: { type: 'number' },
        },
        required: ['left', 'center', 'right'],
        description: 'Percentage of goals scored by side (left/center/right)',
      },
      conceded_by_side: {
        type: 'object',
        properties: {
          left: { type: 'number' },
          center: { type: 'number' },
          right: { type: 'number' },
        },
        required: ['left', 'center', 'right'],
        description: 'Percentage of goals conceded by side (left/center/right)',
      },
      duel_success_rate: {
        type: ['number', 'null'],
        description: 'Overall duel success rate as decimal (0-1), null if unavailable',
      },
      ppda: {
        type: ['number', 'null'],
        description: 'Passes allowed per defensive action, null if unavailable',
      },
      set_piece_goals_for: {
        type: 'number',
        description: 'Goals scored from set pieces this season',
      },
      set_piece_goals_against: {
        type: 'number',
        description: 'Goals conceded from set pieces this season',
      },
      key_players: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            position: { type: 'string' },
            jersey_number: { type: 'string' },
            goals: { type: 'number' },
            assists: { type: 'number' },
            minutes_played: { type: 'number' },
            rating: { type: 'number', description: 'Average rating if available' },
          },
          required: ['name', 'position', 'jersey_number', 'goals', 'assists', 'minutes_played'],
        },
        description: 'Key players of the team',
      },
    },
    required: [
      'last_8_games',
      'preferred_formation',
      'xg_for',
      'xg_against',
      'goals_by_side',
      'conceded_by_side',
      'duel_success_rate',
      'ppda',
      'set_piece_goals_for',
      'set_piece_goals_against',
      'key_players',
    ],
  },
};

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { team, league, data_availability } = body as {
      team: string;
      league: string;
      data_availability: DataAvailability;
    };

    if (!team || !league || !data_availability) {
      throw new AnalysisError(
        'Team, Liga und Datenverfügbarkeit müssen angegeben werden.',
        400
      );
    }

    const hasAnyData =
      data_availability.fbref ||
      data_availability.sofascore ||
      data_availability.transfermarkt;

    if (!hasAnyData) {
      throw new AnalysisError(
        'Keine Statistik-Daten verfügbar für dieses Team',
        400
      );
    }

    const sources: string[] = [];
    if (data_availability.fbref) sources.push('fbref.com');
    if (data_availability.sofascore) sources.push('sofascore.com');
    if (data_availability.transfermarkt) sources.push('transfermarkt.de');

    const message = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 4096,
      temperature: 0,
      system: `Du bist ein Fußball-Datenanalyst. Suche und kompiliere aktuelle Statistiken für das angegebene Team. Nutze dein Wissen über die folgenden Datenquellen: ${sources.join(', ')}. Antworte ausschließlich über das bereitgestellte Tool.`,
      tools: [statsToolSchema],
      tool_choice: { type: 'tool', name: 'report_team_stats' },
      messages: [
        {
          role: 'user',
          content: `Kompiliere detaillierte Statistiken für "${team}" in der "${league}". Ich brauche: die letzten 8 Spiele, bevorzugte Formation, xG (für und gegen), Torverteilung nach Seite (links/mitte/rechts), Gegentore nach Seite, Zweikampfquote, PPDA, Standards-Tore (für und gegen) und die wichtigsten Spieler mit ihren Statistiken.`,
        },
      ],
    });

    const toolBlock = message.content.find(
      (block) => block.type === 'tool_use'
    );
    if (!toolBlock || toolBlock.type !== 'tool_use') {
      throw new AnalysisError(
        'Keine strukturierte Antwort von der KI erhalten.',
        500
      );
    }

    const input = toolBlock.input as {
      last_8_games: GameResult[];
      preferred_formation: string;
      xg_for: number | null;
      xg_against: number | null;
      goals_by_side: SideDistribution;
      conceded_by_side: SideDistribution;
      duel_success_rate: number | null;
      ppda: number | null;
      set_piece_goals_for: number;
      set_piece_goals_against: number;
      key_players: KeyPlayer[];
    };

    const statsData: StatsData = {
      last_8_games: input.last_8_games,
      preferred_formation: input.preferred_formation,
      xg_for: input.xg_for,
      xg_against: input.xg_against,
      goals_by_side: input.goals_by_side,
      conceded_by_side: input.conceded_by_side,
      duel_success_rate: input.duel_success_rate,
      ppda: input.ppda,
      set_piece_goals_for: input.set_piece_goals_for,
      set_piece_goals_against: input.set_piece_goals_against,
      key_players: input.key_players,
    };

    return Response.json(statsData);
  } catch (error) {
    return errorResponse(error);
  }
}
