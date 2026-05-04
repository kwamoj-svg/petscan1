import Anthropic from '@anthropic-ai/sdk';
import { LeagueDetectionResult, Pipeline, DataAvailability } from '@/types/analysis';
import { errorResponse, AnalysisError } from '@/lib/errors';

const anthropic = new Anthropic();

const dataAvailabilityTool: Anthropic.Tool = {
  name: 'report_data_availability',
  description:
    'Report data availability for a football team across fbref, sofascore, and transfermarkt.',
  input_schema: {
    type: 'object' as const,
    properties: {
      fbref: {
        type: 'boolean',
        description: 'Whether fbref.com has data for this team/league.',
      },
      sofascore: {
        type: 'boolean',
        description: 'Whether sofascore.com has data for this team/league.',
      },
      transfermarkt: {
        type: 'boolean',
        description: 'Whether transfermarkt.de has data for this team/league.',
      },
    },
    required: ['fbref', 'sofascore', 'transfermarkt'],
  },
};

function calculatePipeline(score: number): Pipeline {
  if (score === 0) return 'video_only';
  if (score <= 2) return 'hybrid';
  return 'stats_and_video';
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { team, league } = body;

    if (!team || !league) {
      throw new AnalysisError('Team und Liga müssen angegeben werden.', 400);
    }

    const message = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1024,
      temperature: 0,
      system:
        'Du bist ein Fußball-Datenanalyst. Deine Aufgabe ist es zu bestimmen, ob die Plattformen fbref.com, sofascore.com und transfermarkt.de Daten für ein bestimmtes Team und eine bestimmte Liga haben. Antworte ausschließlich über das bereitgestellte Tool.',
      tools: [dataAvailabilityTool],
      tool_choice: { type: 'tool', name: 'report_data_availability' },
      messages: [
        {
          role: 'user',
          content: `Prüfe die Datenverfügbarkeit für das Team "${team}" in der Liga "${league}". Haben fbref.com, sofascore.com und transfermarkt.de Daten für dieses Team?`,
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
      fbref: boolean;
      sofascore: boolean;
      transfermarkt: boolean;
    };

    const overall_score = [input.fbref, input.sofascore, input.transfermarkt].filter(
      Boolean
    ).length;

    const data_availability: DataAvailability = {
      fbref: input.fbref,
      sofascore: input.sofascore,
      transfermarkt: input.transfermarkt,
      overall_score,
    };

    const pipeline = calculatePipeline(overall_score);

    const result: LeagueDetectionResult = {
      team,
      league,
      data_availability,
      pipeline,
    };

    return Response.json(result);
  } catch (error) {
    return errorResponse(error);
  }
}
