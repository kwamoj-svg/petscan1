export interface DataAvailability {
  fbref: boolean;
  sofascore: boolean;
  transfermarkt: boolean;
  overall_score: number;
}

export type Pipeline = 'video_only' | 'hybrid' | 'stats_and_video';

export interface LeagueDetectionResult {
  team: string;
  league: string;
  data_availability: DataAvailability;
  pipeline: Pipeline;
}

export interface GameResult {
  date: string;
  opponent: string;
  score_for: number;
  score_against: number;
  home: boolean;
}

export interface KeyPlayer {
  name: string;
  position: string;
  jersey_number: string;
  goals: number;
  assists: number;
  minutes_played: number;
  rating?: number;
}

export interface SideDistribution {
  left: number;
  center: number;
  right: number;
}

export interface StatsData {
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
}

export interface DuelPosition {
  x: number;
  y: number;
  won: boolean;
}

export interface PlayerTracking {
  player_id: string;
  team: 'A' | 'B';
  jersey_number: string;
  position_label: string;
  avg_position_x: number;
  avg_position_y: number;
  defensive_return_rate: number;
  avg_defensive_position_meter: number;
  sprint_count: number;
  pressing_rate: number;
  duel_positions: DuelPosition[];
  heatmap_data: [number, number][];
}

export type VideoPipelineType = 'fixed_camera' | 'broadcast';

export interface VideoAnalysisResult {
  pipeline_type: VideoPipelineType;
  players: PlayerTracking[];
  total_frames_analyzed: number;
  video_duration_seconds: number;
}

export interface FormationData {
  formation_with_ball: string;
  formation_without_ball: string;
  formation_first_half: string;
  formation_second_half: string;
  changed_formation: boolean;
  formation_change_minute: number | null;
}

export type DefensiveRating = 'Defensiv schwach' | 'Defensiv mittel' | 'Defensiv stark';
export type PressingLabel = 'Kein Pressing' | 'Mittleres Pressing' | 'Hohes Pressing';
export type DefensiveLineLabel = 'Tiefe Abwehr' | 'Mittlere Abwehrlinie' | 'Hohe Abwehrlinie';

export interface PlayerWeakness {
  player_id: string;
  jersey_number: string;
  position: string;
  defensive_return_label: DefensiveRating;
  defensive_return_rate: number;
  leaves_opponent_free: boolean;
  avg_distance_to_opponent: number | null;
}

export interface TeamWeaknesses {
  defensive_line_height: DefensiveLineLabel;
  defensive_line_meters: number;
  pressing_label: PressingLabel;
  avg_pressing_position: number;
  player_weaknesses: PlayerWeakness[];
}

export type Confidence = 'HIGH' | 'MEDIUM' | 'CONFLICT';

export interface EvidenceSource {
  available: boolean;
  value: string;
  source: string;
}

export interface WeightedFinding {
  finding: string;
  stats_evidence: EvidenceSource;
  video_evidence: EvidenceSource;
  confidence: Confidence;
  confidence_reason: string;
}

export interface HybridWeightResult {
  findings: WeightedFinding[];
}

export interface GeminiObservation {
  player: string;
  position: string;
  observation: string;
  exploitation: string;
}

export interface GeminiTacticsResult {
  attack_preferred_side: 'left' | 'center' | 'right';
  build_up_style: 'short' | 'long' | 'mixed';
  pressing_intensity: 'low' | 'medium' | 'high';
  defensive_line_height: 'low' | 'medium' | 'high';
  set_piece_danger: 'low' | 'medium' | 'high';
  transition_speed: 'slow' | 'medium' | 'fast';
  key_observations: GeminiObservation[];
}

export interface AnalysisReport {
  team: string;
  league: string;
  date: string;
  pipeline: Pipeline;
  formation: FormationData;
  attack_pattern: {
    preferred_side: { value: string; confidence: Confidence };
    build_up: { value: string; confidence: Confidence };
    transition: { value: string; confidence: Confidence };
    set_pieces: { value: string; confidence: Confidence };
  };
  defensive_behavior: {
    pressing_line: { value: string; confidence: Confidence };
    pressing_intensity: { value: string; confidence: Confidence };
    defensive_line: { value: string; confidence: Confidence };
  };
  player_weaknesses: {
    jersey_number: string;
    position: string;
    weakness: string;
    recommendation: string;
    confidence: Confidence;
  }[];
  key_players: {
    jersey_number: string;
    position: string;
    reason: string;
  }[];
  tactical_recommendations: string[];
  data_basis: {
    sources: string[];
    video_pipeline: string;
    analysis_quality: 'HIGH' | 'MEDIUM' | 'LOW';
    notes: string[];
  };
  report_text: string;
}

export type AnalysisStep =
  | 'idle'
  | 'detecting_league'
  | 'searching_data'
  | 'compressing_video'
  | 'detecting_video_type'
  | 'tracking_players'
  | 'calculating_formation'
  | 'analyzing_weaknesses'
  | 'weighting_data'
  | 'generating_report'
  | 'complete'
  | 'error';

export interface AnalysisState {
  step: AnalysisStep;
  message: string;
  progress: number;
  league_result?: LeagueDetectionResult;
  stats_data?: StatsData;
  video_result?: VideoAnalysisResult;
  formation?: FormationData;
  weaknesses?: TeamWeaknesses;
  weighted_findings?: HybridWeightResult;
  report?: AnalysisReport;
  error?: string;
}
