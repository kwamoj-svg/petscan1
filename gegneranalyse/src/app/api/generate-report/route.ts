import Anthropic from '@anthropic-ai/sdk';
import {
  Pipeline,
  FormationData,
  HybridWeightResult,
  TeamWeaknesses,
  StatsData,
  VideoAnalysisResult,
  GeminiTacticsResult,
  AnalysisReport,
  Confidence,
} from '@/types/analysis';
import { errorResponse, AnalysisError } from '@/lib/errors';

const anthropic = new Anthropic();

const REPORT_TEMPLATE = `# GEGNERANALYSE: {team}
**Liga:** {league}
**Datum:** {date}
**Datengrundlage:** {data_basis}

---

## 1. FORMATION & SYSTEM
- Formation mit Ball: {formation_with_ball}
- Formation ohne Ball: {formation_without_ball}
- Formationswechsel: {formation_change}

## 2. ANGRIFFSMUSTER
- Bevorzugte Seite: [Erkenntnis + Konfidenz]
- Spielaufbau: [Erkenntnis + Konfidenz]
- Umschaltspiel: [Erkenntnis + Konfidenz]
- Standardsituationen: [Erkenntnis + Konfidenz]

## 3. DEFENSIVVERHALTEN
- Pressing-Linie: [Erkenntnis + Konfidenz]
- Pressing-Intensität: [Erkenntnis + Konfidenz]
- Abwehrkette: [Erkenntnis + Konfidenz]

## 4. INDIVIDUELLE SCHWACHSTELLEN
Für jeden Spieler:
- Spieler #[Nummer] ([Position]): [Schwachstelle] → Empfehlung [Konfidenz]

## 5. SCHLÜSSELSPIELER
Für jeden Schlüsselspieler:
- #[Nummer] ([Position]): [Warum gefährlich]

## 6. TAKTISCHE EMPFEHLUNGEN
1. [Empfehlung basierend auf Erkenntnissen]
2. [Empfehlung basierend auf Erkenntnissen]
3. [Empfehlung basierend auf Erkenntnissen]

---
**Analyse-Qualität:** {analysis_quality}
**Hinweise:** {notes}`;

interface GenerateReportInput {
  team: string;
  league: string;
  pipeline: Pipeline;
  formation: FormationData;
  weighted_findings: HybridWeightResult;
  weaknesses: TeamWeaknesses;
  stats_data?: StatsData;
  video_result?: VideoAnalysisResult;
  gemini_tactics?: GeminiTacticsResult;
}

function determineAnalysisQuality(
  stats_data?: StatsData,
  video_result?: VideoAnalysisResult
): 'HIGH' | 'MEDIUM' | 'LOW' {
  if (stats_data && video_result) return 'HIGH';
  if (stats_data || video_result) return 'MEDIUM';
  return 'LOW';
}

function determineSources(
  pipeline: Pipeline,
  stats_data?: StatsData,
  video_result?: VideoAnalysisResult
): string[] {
  const sources: string[] = [];
  if (stats_data) sources.push('Statistik-Daten (FBref, Sofascore, Transfermarkt)');
  if (video_result) {
    sources.push(
      `Video-Analyse (${video_result.pipeline_type === 'fixed_camera' ? 'Festkamera' : 'TV-Übertragung'})`
    );
  }
  if (sources.length === 0) {
    sources.push(`Pipeline: ${pipeline}`);
  }
  return sources;
}

function findFindingConfidence(
  findings: HybridWeightResult,
  keyword: string
): { value: string; confidence: Confidence } {
  const found = findings.findings.find((f) =>
    f.finding.toLowerCase().includes(keyword.toLowerCase())
  );
  if (found) {
    const evidenceText = found.stats_evidence.available
      ? found.stats_evidence.value
      : found.video_evidence.available
        ? found.video_evidence.value
        : found.finding;
    return { value: evidenceText, confidence: found.confidence };
  }
  return { value: 'Keine Daten verfügbar', confidence: 'MEDIUM' };
}

function buildStructuredReport(input: GenerateReportInput, reportText: string): AnalysisReport {
  const {
    team,
    league,
    pipeline,
    formation,
    weighted_findings,
    weaknesses,
    stats_data,
    video_result,
    gemini_tactics,
  } = input;

  const analysisQuality = determineAnalysisQuality(stats_data, video_result);
  const sources = determineSources(pipeline, stats_data, video_result);

  // Build attack_pattern from findings and gemini_tactics
  const preferredSide = gemini_tactics
    ? {
        value: `Bevorzugte Seite: ${gemini_tactics.attack_preferred_side}`,
        confidence: findFindingConfidence(weighted_findings, 'Schwachstelle').confidence,
      }
    : findFindingConfidence(weighted_findings, 'Schwachstelle');

  const buildUp = gemini_tactics
    ? {
        value: `Spielaufbau: ${gemini_tactics.build_up_style}`,
        confidence: 'MEDIUM' as Confidence,
      }
    : { value: 'Keine Daten verfügbar', confidence: 'MEDIUM' as Confidence };

  const transition = gemini_tactics
    ? {
        value: `Umschaltgeschwindigkeit: ${gemini_tactics.transition_speed}`,
        confidence: 'MEDIUM' as Confidence,
      }
    : { value: 'Keine Daten verfügbar', confidence: 'MEDIUM' as Confidence };

  const setPieces = findFindingConfidence(weighted_findings, 'Standardsituation');

  // Build defensive_behavior
  const pressingLine = {
    value: `${weaknesses.pressing_label} (Durchschnitt: ${weaknesses.avg_pressing_position}m)`,
    confidence: findFindingConfidence(weighted_findings, 'Pressing').confidence,
  };

  const pressingIntensity = gemini_tactics
    ? {
        value: `Pressing-Intensität: ${gemini_tactics.pressing_intensity}`,
        confidence: findFindingConfidence(weighted_findings, 'Pressing').confidence,
      }
    : {
        value: weaknesses.pressing_label,
        confidence: findFindingConfidence(weighted_findings, 'Pressing').confidence,
      };

  const defensiveLine = {
    value: `${weaknesses.defensive_line_height} (${weaknesses.defensive_line_meters}m)`,
    confidence: 'MEDIUM' as Confidence,
  };

  // Build player_weaknesses from TeamWeaknesses
  const playerWeaknesses = weaknesses.player_weaknesses.map((pw) => {
    const finding = weighted_findings.findings.find(
      (f) => f.finding.includes(`#${pw.jersey_number}`)
    );
    return {
      jersey_number: pw.jersey_number,
      position: pw.position,
      weakness: `${pw.defensive_return_label} (Rücklaufquote: ${(pw.defensive_return_rate * 100).toFixed(0)}%)${pw.leaves_opponent_free ? ', lässt Gegenspieler frei' : ''}`,
      recommendation: pw.leaves_opponent_free
        ? `Gegenspieler von #${pw.jersey_number} gezielt einsetzen, Raum hinter ihm bespielen`
        : `Hohe Laufbereitschaft gegen #${pw.jersey_number} zeigen`,
      confidence: finding?.confidence ?? ('MEDIUM' as Confidence),
    };
  });

  // Build key_players from stats or gemini
  const keyPlayers: { jersey_number: string; position: string; reason: string }[] = [];
  if (stats_data?.key_players) {
    for (const kp of stats_data.key_players.slice(0, 5)) {
      keyPlayers.push({
        jersey_number: kp.jersey_number,
        position: kp.position,
        reason: `${kp.goals} Tore, ${kp.assists} Vorlagen in ${kp.minutes_played} Minuten${kp.rating ? ` (Bewertung: ${kp.rating})` : ''}`,
      });
    }
  }
  if (gemini_tactics?.key_observations) {
    for (const obs of gemini_tactics.key_observations) {
      if (!keyPlayers.find((kp) => kp.jersey_number === obs.player)) {
        keyPlayers.push({
          jersey_number: obs.player,
          position: obs.position,
          reason: obs.observation,
        });
      }
    }
  }

  // Build tactical recommendations from findings
  const tacticalRecommendations: string[] = [];
  for (const finding of weighted_findings.findings) {
    if (finding.confidence === 'HIGH') {
      tacticalRecommendations.push(
        `[HIGH ✓] ${finding.finding}: ${finding.stats_evidence.available ? finding.stats_evidence.value : finding.video_evidence.value}`
      );
    }
  }
  // Add medium confidence if we need more recommendations
  if (tacticalRecommendations.length < 3) {
    for (const finding of weighted_findings.findings) {
      if (finding.confidence === 'MEDIUM' && tacticalRecommendations.length < 5) {
        tacticalRecommendations.push(
          `[MEDIUM ~] ${finding.finding}: ${finding.stats_evidence.available ? finding.stats_evidence.value : finding.video_evidence.value}`
        );
      }
    }
  }

  const notes: string[] = [];
  if (!stats_data) notes.push('Keine Statistik-Daten verfügbar.');
  if (!video_result) notes.push('Keine Video-Analyse verfügbar.');
  if (video_result?.pipeline_type === 'broadcast') {
    notes.push('Video-Analyse basiert auf TV-Übertragung (eingeschränkte Sichtbarkeit).');
  }

  const today = new Date().toISOString().split('T')[0];

  return {
    team,
    league,
    date: today,
    pipeline,
    formation,
    attack_pattern: {
      preferred_side: preferredSide,
      build_up: buildUp,
      transition,
      set_pieces: setPieces,
    },
    defensive_behavior: {
      pressing_line: pressingLine,
      pressing_intensity: pressingIntensity,
      defensive_line: defensiveLine,
    },
    player_weaknesses: playerWeaknesses,
    key_players: keyPlayers,
    tactical_recommendations: tacticalRecommendations,
    data_basis: {
      sources,
      video_pipeline: video_result?.pipeline_type ?? 'none',
      analysis_quality: analysisQuality,
      notes,
    },
    report_text: reportText,
  };
}

export async function POST(request: Request) {
  try {
    const body: GenerateReportInput = await request.json();
    const {
      team,
      league,
      pipeline,
      formation,
      weighted_findings,
      weaknesses,
      stats_data,
      video_result,
      gemini_tactics,
    } = body;

    if (!team || !league || !pipeline || !formation || !weighted_findings || !weaknesses) {
      throw new AnalysisError(
        'Team, Liga, Pipeline, Formation, gewichtete Erkenntnisse und Schwachstellen müssen angegeben werden.',
        400
      );
    }

    const analysisQuality = determineAnalysisQuality(stats_data, video_result);

    const systemPrompt = `Du bist ein professioneller Fußball-Analyst. Du erhältst strukturierte JSON-Daten einer Gegneranalyse. Fülle das folgende Report-Template EXAKT aus. Verwende NUR die bereitgestellten Daten. Erfinde KEINE zusätzlichen Informationen. Markiere jede Erkenntnis mit der entsprechenden Konfidenz [HIGH ✓] [MEDIUM ~] [CONFLICT ⚠].

Report-Template:
${REPORT_TEMPLATE}`;

    const userMessage = `Erstelle den Gegneranalyse-Report für folgende Daten:

Team: ${team}
Liga: ${league}
Analyse-Qualität: ${analysisQuality}

Formation:
${JSON.stringify(formation, null, 2)}

Gewichtete Erkenntnisse:
${JSON.stringify(weighted_findings, null, 2)}

Schwachstellen:
${JSON.stringify(weaknesses, null, 2)}

${stats_data ? `Statistik-Daten:\n${JSON.stringify(stats_data, null, 2)}` : 'Keine Statistik-Daten verfügbar.'}

${video_result ? `Video-Analyse:\n${JSON.stringify(video_result, null, 2)}` : 'Keine Video-Analyse verfügbar.'}

${gemini_tactics ? `Taktische Analyse (Gemini):\n${JSON.stringify(gemini_tactics, null, 2)}` : 'Keine Gemini-Taktikanalyse verfügbar.'}

Fülle das Template vollständig aus. Verwende ausschließlich die bereitgestellten Daten.`;

    const message = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 4096,
      temperature: 0,
      system: systemPrompt,
      messages: [
        {
          role: 'user',
          content: userMessage,
        },
      ],
    });

    const textBlock = message.content.find((block) => block.type === 'text');
    if (!textBlock || textBlock.type !== 'text') {
      throw new AnalysisError('Keine Textantwort von der KI erhalten.', 500);
    }

    const reportText = textBlock.text;
    const report = buildStructuredReport(body, reportText);

    return Response.json(report);
  } catch (error) {
    return errorResponse(error);
  }
}
