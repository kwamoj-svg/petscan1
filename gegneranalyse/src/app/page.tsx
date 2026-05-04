'use client';

import { useState, useRef } from 'react';
import {
  AnalysisStep,
  AnalysisState,
  AnalysisReport,
  FormationData,
  StatsData,
  VideoAnalysisResult,
} from '@/types/analysis';
import { STEP_MESSAGES } from '@/lib/constants';
import StatusDisplay from '@/components/StatusDisplay';
import ReportDisplay from '@/components/ReportDisplay';
import FormationPitch from '@/components/FormationPitch';
import HeatmapDisplay from '@/components/HeatmapDisplay';
import PdfExportButton from '@/components/PdfExportButton';

const STEP_PROGRESS: Record<AnalysisStep, number> = {
  idle: 0,
  detecting_league: 10,
  searching_data: 25,
  compressing_video: 35,
  detecting_video_type: 40,
  tracking_players: 55,
  calculating_formation: 65,
  analyzing_weaknesses: 75,
  weighting_data: 85,
  generating_report: 95,
  complete: 100,
  error: 0,
};

export default function HomePage() {
  const [team, setTeam] = useState('');
  const [league, setLeague] = useState('');
  const [videoFile, setVideoFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [state, setState] = useState<AnalysisState>({
    step: 'idle',
    message: STEP_MESSAGES.idle,
    progress: 0,
  });

  const isRunning =
    state.step !== 'idle' && state.step !== 'complete' && state.step !== 'error';

  function updateStep(step: AnalysisStep) {
    setState((prev) => ({
      ...prev,
      step,
      message: STEP_MESSAGES[step],
      progress: STEP_PROGRESS[step],
    }));
  }

  async function runAnalysis() {
    if (!team.trim()) return;

    setState({
      step: 'detecting_league',
      message: STEP_MESSAGES.detecting_league,
      progress: STEP_PROGRESS.detecting_league,
    });

    try {
      // 1. Detect league
      const leagueRes = await fetch('/api/detect-league', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ team: team.trim(), league: league.trim() }),
      });
      if (!leagueRes.ok) throw new Error('Liga-Erkennung fehlgeschlagen');
      const leagueData = await leagueRes.json();

      setState((prev) => ({ ...prev, league_result: leagueData }));

      // 2. Fetch stats if pipeline supports it
      let statsData: StatsData | undefined = undefined;
      if (leagueData.pipeline === 'hybrid' || leagueData.pipeline === 'stats_and_video') {
        updateStep('searching_data');
        const statsRes = await fetch('/api/fetch-stats', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            team: leagueData.team,
            league: leagueData.league,
            data_availability: leagueData.data_availability,
          }),
        });
        if (!statsRes.ok) throw new Error('Datensuche fehlgeschlagen');
        statsData = await statsRes.json();
        setState((prev) => ({ ...prev, stats_data: statsData }));
      }

      // 3. Analyze video if uploaded
      let videoResult: VideoAnalysisResult | undefined = undefined;
      if (videoFile) {
        updateStep('compressing_video');
        // Small delay to show compression step
        await new Promise((r) => setTimeout(r, 500));

        updateStep('detecting_video_type');
        await new Promise((r) => setTimeout(r, 300));

        updateStep('tracking_players');
        const formData = new FormData();
        formData.append('video', videoFile);
        formData.append('team', leagueData.team);

        const videoRes = await fetch('/api/analyze-video', {
          method: 'POST',
          body: formData,
        });
        if (!videoRes.ok) throw new Error('Video-Analyse fehlgeschlagen');
        videoResult = await videoRes.json();
        setState((prev) => ({ ...prev, video_result: videoResult }));
      }

      // 4. Calculate formation
      updateStep('calculating_formation');
      const formationRes = await fetch('/api/calculate-formation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          players: videoResult?.players ?? [],
          stats_formation: statsData?.preferred_formation,
        }),
      });
      if (!formationRes.ok) throw new Error('Formationsberechnung fehlgeschlagen');
      const formationData: FormationData = await formationRes.json();
      setState((prev) => ({ ...prev, formation: formationData }));

      // 5. Calculate weaknesses
      updateStep('analyzing_weaknesses');
      const weaknessRes = await fetch('/api/calculate-weaknesses', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          players: videoResult?.players ?? [],
          formation: formationData,
        }),
      });
      if (!weaknessRes.ok) throw new Error('Schwachstellenanalyse fehlgeschlagen');
      const weaknesses = await weaknessRes.json();
      setState((prev) => ({ ...prev, weaknesses }));

      // 6. Weight findings
      updateStep('weighting_data');
      const weightRes = await fetch('/api/weight-findings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          stats_data: statsData,
          video_result: videoResult,
          formation: formationData,
          weaknesses,
          pipeline: leagueData.pipeline,
        }),
      });
      if (!weightRes.ok) throw new Error('Gewichtung fehlgeschlagen');
      const weightedFindings = await weightRes.json();
      setState((prev) => ({ ...prev, weighted_findings: weightedFindings }));

      // 7. Generate report
      updateStep('generating_report');
      const reportRes = await fetch('/api/generate-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          team: leagueData.team,
          league: leagueData.league,
          pipeline: leagueData.pipeline,
          stats_data: statsData,
          video_result: videoResult,
          formation: formationData,
          weaknesses,
          weighted_findings: weightedFindings,
        }),
      });
      if (!reportRes.ok) throw new Error('Report-Erstellung fehlgeschlagen');
      const report: AnalysisReport = await reportRes.json();

      setState((prev) => ({
        ...prev,
        step: 'complete',
        message: STEP_MESSAGES.complete,
        progress: 100,
        report,
      }));
    } catch (err) {
      const errorMsg =
        err instanceof Error ? err.message : 'Ein unbekannter Fehler ist aufgetreten';
      setState((prev) => ({
        ...prev,
        step: 'error',
        message: STEP_MESSAGES.error,
        progress: prev.progress,
        error: errorMsg,
      }));
    }
  }

  return (
    <div className="min-h-screen bg-scout-dark">
      {/* Header */}
      <header className="border-b border-scout-border bg-scout-card/50 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-5xl mx-auto px-4 py-4 flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-wider text-gray-100">
              GEGNERANALYSE
            </h1>
            <p className="text-sm text-gray-500 mt-0.5">Professionelles Fussball-Scouting</p>
          </div>
          <div className="w-8 h-8 rounded-full bg-scout-accent/20 flex items-center justify-center">
            <svg className="w-4 h-4 text-scout-accent" fill="currentColor" viewBox="0 0 20 20">
              <path d="M10 2a8 8 0 100 16 8 8 0 000-16zm0 14.5A6.5 6.5 0 1116.5 10 6.508 6.508 0 0110 16.5z" />
              <circle cx="10" cy="10" r="2" />
            </svg>
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-8 space-y-8">
        {/* Input Form */}
        {state.step === 'idle' || state.step === 'error' ? (
          <div className="max-w-xl mx-auto">
            <div className="bg-scout-card border border-scout-border rounded-xl p-6 space-y-5">
              <h2 className="text-lg font-semibold text-gray-100">Neue Analyse starten</h2>

              {/* Team name */}
              <div>
                <label htmlFor="team" className="block text-sm font-medium text-gray-400 mb-1.5">
                  Mannschaftsname *
                </label>
                <input
                  id="team"
                  type="text"
                  value={team}
                  onChange={(e) => setTeam(e.target.value)}
                  placeholder="z.B. Borussia Dortmund"
                  className="w-full bg-scout-dark border border-scout-border rounded-lg px-4 py-2.5 text-gray-200 placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-scout-accent/50 focus:border-scout-accent transition-colors"
                />
              </div>

              {/* League */}
              <div>
                <label htmlFor="league" className="block text-sm font-medium text-gray-400 mb-1.5">
                  Liga
                </label>
                <input
                  id="league"
                  type="text"
                  value={league}
                  onChange={(e) => setLeague(e.target.value)}
                  placeholder="Bundesliga, Kreisliga Westfalen, 2. Liga..."
                  className="w-full bg-scout-dark border border-scout-border rounded-lg px-4 py-2.5 text-gray-200 placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-scout-accent/50 focus:border-scout-accent transition-colors"
                />
              </div>

              {/* Video upload */}
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1.5">
                  Videomaterial (optional)
                </label>
                <div
                  onClick={() => fileInputRef.current?.click()}
                  className="w-full border-2 border-dashed border-scout-border rounded-lg p-6 text-center cursor-pointer hover:border-scout-accent/50 transition-colors"
                >
                  {videoFile ? (
                    <div className="space-y-1">
                      <p className="text-sm text-gray-300">{videoFile.name}</p>
                      <p className="text-xs text-gray-500">
                        {(videoFile.size / (1024 * 1024)).toFixed(1)} MB
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      <svg
                        className="w-8 h-8 mx-auto text-gray-600"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={1.5}
                          d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
                        />
                      </svg>
                      <p className="text-sm text-gray-500">
                        Klicken zum Hochladen oder Datei hierher ziehen
                      </p>
                      <p className="text-xs text-gray-600">MP4, MOV, AVI (max. 500 MB)</p>
                    </div>
                  )}
                </div>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept="video/*"
                  className="hidden"
                  onChange={(e) => setVideoFile(e.target.files?.[0] ?? null)}
                />
              </div>

              {/* Error message */}
              {state.step === 'error' && state.error && (
                <div className="bg-confidence-conflict/10 border border-confidence-conflict/20 rounded-lg p-3">
                  <p className="text-sm text-confidence-conflict">{state.error}</p>
                </div>
              )}

              {/* Submit button */}
              <button
                onClick={runAnalysis}
                disabled={!team.trim() || isRunning}
                className="w-full bg-scout-accent hover:bg-blue-600 disabled:bg-scout-accent/30 disabled:cursor-not-allowed text-white font-semibold py-3 rounded-lg transition-colors"
              >
                Analyse starten
              </button>
            </div>
          </div>
        ) : null}

        {/* Status Display */}
        {isRunning && (
          <div className="max-w-xl mx-auto">
            <StatusDisplay
              step={state.step}
              message={state.message}
              progress={state.progress}
            />
          </div>
        )}

        {/* Report Display */}
        {state.step === 'complete' && state.report && (
          <div className="space-y-8">
            {/* Actions bar */}
            <div className="flex items-center justify-between">
              <h2 className="text-xl font-bold text-gray-100">Analyse-Ergebnis</h2>
              <div className="flex items-center gap-3">
                <PdfExportButton report={state.report} />
                <button
                  onClick={() => {
                    setState({
                      step: 'idle',
                      message: STEP_MESSAGES.idle,
                      progress: 0,
                    });
                    setTeam('');
                    setLeague('');
                    setVideoFile(null);
                  }}
                  className="px-5 py-2.5 bg-scout-card border border-scout-border rounded-lg text-gray-400 hover:text-gray-200 hover:bg-scout-border transition-colors text-sm"
                >
                  Neue Analyse
                </button>
              </div>
            </div>

            {/* Formation Pitch */}
            {state.report.formation && (
              <FormationPitch
                formation={state.report.formation}
                players={state.video_result?.players}
              />
            )}

            {/* Heatmap (only if video data available) */}
            {state.video_result?.players && state.video_result.players.length > 0 && (
              <HeatmapDisplay players={state.video_result.players} />
            )}

            {/* Full Report */}
            <ReportDisplay report={state.report} />
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-scout-border mt-16">
        <div className="max-w-5xl mx-auto px-4 py-6 text-center text-xs text-gray-600">
          Gegneranalyse - Professionelles Scouting Tool
        </div>
      </footer>
    </div>
  );
}
