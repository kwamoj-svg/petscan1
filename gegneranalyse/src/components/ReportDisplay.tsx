'use client';

import { AnalysisReport } from '@/types/analysis';
import ConfidenceBadge from './ConfidenceBadge';

interface ReportDisplayProps {
  report: AnalysisReport;
}

export default function ReportDisplay({ report }: ReportDisplayProps) {
  return (
    <div id="report-content" className="space-y-6">
      {/* Header */}
      <div className="bg-scout-card border border-scout-border rounded-xl p-6">
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-2xl font-bold text-gray-100">{report.team}</h2>
            <p className="text-gray-400 mt-1">{report.league}</p>
          </div>
          <div className="text-right text-sm text-gray-500">
            <p>{report.date}</p>
            <p className="mt-1">
              Pipeline:{' '}
              <span className="text-gray-300">
                {report.pipeline === 'hybrid'
                  ? 'Hybrid'
                  : report.pipeline === 'stats_and_video'
                  ? 'Statistik + Video'
                  : 'Nur Video'}
              </span>
            </p>
          </div>
        </div>
      </div>

      {/* Formation */}
      <div className="bg-scout-card border border-scout-border rounded-xl p-6">
        <h3 className="text-lg font-semibold text-gray-100 mb-4">Formation</h3>
        <div className="grid grid-cols-2 gap-4">
          <div className="bg-scout-dark/50 rounded-lg p-4">
            <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">Mit Ball</p>
            <p className="text-xl font-bold text-gray-100">{report.formation.formation_with_ball}</p>
          </div>
          <div className="bg-scout-dark/50 rounded-lg p-4">
            <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">Ohne Ball</p>
            <p className="text-xl font-bold text-gray-100">{report.formation.formation_without_ball}</p>
          </div>
          {report.formation.changed_formation && (
            <div className="col-span-2 bg-confidence-medium/10 border border-confidence-medium/20 rounded-lg p-3">
              <p className="text-sm text-confidence-medium">
                Formationswechsel in Minute {report.formation.formation_change_minute}:{' '}
                {report.formation.formation_first_half} &rarr; {report.formation.formation_second_half}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Angriffsmuster */}
      <div className="bg-scout-card border border-scout-border rounded-xl p-6">
        <h3 className="text-lg font-semibold text-gray-100 mb-4">Angriffsmuster</h3>
        <div className="space-y-3">
          {([
            ['Bevorzugte Seite', report.attack_pattern.preferred_side],
            ['Spielaufbau', report.attack_pattern.build_up],
            ['Umschaltspiel', report.attack_pattern.transition],
            ['Standards', report.attack_pattern.set_pieces],
          ] as const).map(([label, data]) => (
            <div key={label} className="flex items-center justify-between bg-scout-dark/50 rounded-lg px-4 py-3">
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wide">{label}</p>
                <p className="text-gray-200 mt-0.5">{data.value}</p>
              </div>
              <ConfidenceBadge confidence={data.confidence} />
            </div>
          ))}
        </div>
      </div>

      {/* Defensivverhalten */}
      <div className="bg-scout-card border border-scout-border rounded-xl p-6">
        <h3 className="text-lg font-semibold text-gray-100 mb-4">Defensivverhalten</h3>
        <div className="space-y-3">
          {([
            ['Pressinglinie', report.defensive_behavior.pressing_line],
            ['Pressing-Intensitaet', report.defensive_behavior.pressing_intensity],
            ['Abwehrlinie', report.defensive_behavior.defensive_line],
          ] as const).map(([label, data]) => (
            <div key={label} className="flex items-center justify-between bg-scout-dark/50 rounded-lg px-4 py-3">
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wide">{label}</p>
                <p className="text-gray-200 mt-0.5">{data.value}</p>
              </div>
              <ConfidenceBadge confidence={data.confidence} />
            </div>
          ))}
        </div>
      </div>

      {/* Spieler-Schwachstellen */}
      {report.player_weaknesses.length > 0 && (
        <div className="bg-scout-card border border-scout-border rounded-xl p-6">
          <h3 className="text-lg font-semibold text-gray-100 mb-4">Spieler-Schwachstellen</h3>
          <div className="space-y-3">
            {report.player_weaknesses.map((pw, idx) => (
              <div key={idx} className="bg-scout-dark/50 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-scout-border text-sm font-bold text-gray-200">
                      {pw.jersey_number}
                    </span>
                    <span className="text-gray-400 text-sm">{pw.position}</span>
                  </div>
                  <ConfidenceBadge confidence={pw.confidence} />
                </div>
                <p className="text-gray-300 text-sm">{pw.weakness}</p>
                <p className="text-scout-accent text-sm mt-1">Empfehlung: {pw.recommendation}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Schluesselspieler */}
      {report.key_players.length > 0 && (
        <div className="bg-scout-card border border-scout-border rounded-xl p-6">
          <h3 className="text-lg font-semibold text-gray-100 mb-4">Schluesselspieler</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {report.key_players.map((kp, idx) => (
              <div key={idx} className="bg-scout-dark/50 rounded-lg p-4 flex items-start gap-3">
                <span className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-scout-accent/20 text-sm font-bold text-scout-accent flex-shrink-0">
                  {kp.jersey_number}
                </span>
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wide">{kp.position}</p>
                  <p className="text-gray-300 text-sm mt-0.5">{kp.reason}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Taktische Empfehlungen */}
      <div className="bg-scout-card border border-scout-border rounded-xl p-6">
        <h3 className="text-lg font-semibold text-gray-100 mb-4">Taktische Empfehlungen</h3>
        <ol className="space-y-2">
          {report.tactical_recommendations.map((rec, idx) => (
            <li key={idx} className="flex gap-3 text-sm">
              <span className="flex-shrink-0 inline-flex items-center justify-center w-6 h-6 rounded-full bg-scout-accent/20 text-scout-accent text-xs font-bold">
                {idx + 1}
              </span>
              <span className="text-gray-300 pt-0.5">{rec}</span>
            </li>
          ))}
        </ol>
      </div>

      {/* Datenbasis */}
      <div className="bg-scout-card border border-scout-border rounded-xl p-6">
        <h3 className="text-lg font-semibold text-gray-100 mb-4">Datenbasis</h3>
        <div className="space-y-3">
          <div className="flex flex-wrap gap-2">
            {report.data_basis.sources.map((src) => (
              <span
                key={src}
                className="px-3 py-1 bg-scout-dark/50 border border-scout-border rounded-full text-xs text-gray-400"
              >
                {src}
              </span>
            ))}
          </div>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <p className="text-gray-500">Video-Pipeline</p>
              <p className="text-gray-300">{report.data_basis.video_pipeline}</p>
            </div>
            <div>
              <p className="text-gray-500">Analysequalitaet</p>
              <p className="text-gray-300">{report.data_basis.analysis_quality}</p>
            </div>
          </div>
          {report.data_basis.notes.length > 0 && (
            <div className="text-xs text-gray-500 space-y-1">
              {report.data_basis.notes.map((note, idx) => (
                <p key={idx}>* {note}</p>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Volltext-Report */}
      {report.report_text && (
        <div className="bg-scout-card border border-scout-border rounded-xl p-6">
          <h3 className="text-lg font-semibold text-gray-100 mb-4">Vollstaendiger Report</h3>
          <div className="text-gray-300 text-sm leading-relaxed whitespace-pre-wrap">
            {report.report_text}
          </div>
        </div>
      )}
    </div>
  );
}
