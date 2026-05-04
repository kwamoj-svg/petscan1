'use client';

import { AnalysisStep } from '@/types/analysis';
import { STEP_MESSAGES } from '@/lib/constants';

interface StatusDisplayProps {
  step: AnalysisStep;
  message: string;
  progress: number;
}

const ORDERED_STEPS: { key: AnalysisStep; label: string }[] = [
  { key: 'detecting_league', label: 'Liga erkennen' },
  { key: 'searching_data', label: 'Daten suchen' },
  { key: 'compressing_video', label: 'Video komprimieren' },
  { key: 'detecting_video_type', label: 'Video-Typ erkennen' },
  { key: 'tracking_players', label: 'Spieler tracken' },
  { key: 'calculating_formation', label: 'Formation berechnen' },
  { key: 'analyzing_weaknesses', label: 'Schwachstellen analysieren' },
  { key: 'weighting_data', label: 'Daten gewichten' },
  { key: 'generating_report', label: 'Report erstellen' },
];

function getStepIndex(step: AnalysisStep): number {
  return ORDERED_STEPS.findIndex((s) => s.key === step);
}

export default function StatusDisplay({ step, message, progress }: StatusDisplayProps) {
  const currentIndex = getStepIndex(step);
  const isComplete = step === 'complete';
  const isError = step === 'error';

  return (
    <div className="bg-scout-card border border-scout-border rounded-xl p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-gray-100">Analyse-Fortschritt</h3>
        <span className="text-sm text-gray-400">
          {isComplete ? 'Abgeschlossen' : isError ? 'Fehler' : message}
        </span>
      </div>

      {/* Vertical stepper */}
      <div className="space-y-1">
        {ORDERED_STEPS.map((s, idx) => {
          const isActive = s.key === step;
          const isCompleted = isComplete || currentIndex > idx;
          const isSkipped = !isCompleted && !isActive && currentIndex < idx;

          return (
            <div key={s.key} className="flex items-center gap-3 py-1.5">
              {/* Step indicator */}
              <div className="flex-shrink-0">
                {isCompleted ? (
                  <div className="w-6 h-6 rounded-full bg-confidence-high/20 flex items-center justify-center">
                    <svg className="w-3.5 h-3.5 text-confidence-high" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                    </svg>
                  </div>
                ) : isActive ? (
                  <div className="w-6 h-6 rounded-full bg-scout-accent/20 flex items-center justify-center animate-pulse-dot">
                    <div className="w-2.5 h-2.5 rounded-full bg-scout-accent" />
                  </div>
                ) : isError && currentIndex === idx ? (
                  <div className="w-6 h-6 rounded-full bg-confidence-conflict/20 flex items-center justify-center">
                    <span className="text-confidence-conflict text-xs font-bold">!</span>
                  </div>
                ) : (
                  <div className="w-6 h-6 rounded-full bg-scout-border flex items-center justify-center">
                    <div className="w-2 h-2 rounded-full bg-gray-600" />
                  </div>
                )}
              </div>

              {/* Step label */}
              <span
                className={`text-sm ${
                  isActive
                    ? 'text-scout-accent font-medium'
                    : isCompleted
                    ? 'text-gray-300'
                    : 'text-gray-500'
                }`}
              >
                {s.label}
              </span>
            </div>
          );
        })}
      </div>

      {/* Progress bar */}
      <div className="space-y-2">
        <div className="flex justify-between text-xs text-gray-500">
          <span>Fortschritt</span>
          <span>{Math.round(progress)}%</span>
        </div>
        <div className="w-full h-2 bg-scout-border rounded-full overflow-hidden">
          <div
            className="h-full rounded-full bg-gradient-to-r from-scout-accent to-blue-400 transition-all duration-500 ease-out"
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>
    </div>
  );
}
