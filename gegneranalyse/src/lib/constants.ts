export const STEP_MESSAGES: Record<string, string> = {
  idle: 'Bereit zur Analyse',
  detecting_league: 'Liga wird erkannt...',
  searching_data: 'Verfügbare Daten werden gesucht...',
  compressing_video: 'Video wird komprimiert...',
  detecting_video_type: 'Video-Typ wird erkannt...',
  tracking_players: 'Spieler werden getrackt...',
  calculating_formation: 'Formation wird berechnet...',
  analyzing_weaknesses: 'Schwachstellen werden analysiert...',
  weighting_data: 'Daten werden gewichtet...',
  generating_report: 'Report wird erstellt...',
  complete: 'Analyse abgeschlossen',
  error: 'Fehler bei der Analyse',
};

export const DEFENSIVE_RETURN_THRESHOLDS = {
  weak: 0.4,
  strong: 0.6,
} as const;

export const PRESSING_POSITION_THRESHOLD = 55;

export const OPPONENT_DISTANCE_THRESHOLD = 5;

export const DEFENSIVE_LINE_THRESHOLDS = {
  low: 35,
  high: 45,
} as const;

export const FIXED_CAMERA_MIN_SCENE_DURATION = 8;

export const MAX_VIDEO_SIZE_MB = 500;

export const CONFIDENCE_COLORS: Record<string, string> = {
  HIGH: '#22c55e',
  MEDIUM: '#eab308',
  CONFLICT: '#ef4444',
};
