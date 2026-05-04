import { Confidence } from '@/types/analysis';

interface ConfidenceBadgeProps {
  confidence: Confidence;
}

const BADGE_CONFIG: Record<Confidence, { bg: string; text: string; label: string }> = {
  HIGH: {
    bg: 'bg-confidence-high/20',
    text: 'text-confidence-high',
    label: '✓ HIGH',
  },
  MEDIUM: {
    bg: 'bg-confidence-medium/20',
    text: 'text-confidence-medium',
    label: '~ MEDIUM',
  },
  CONFLICT: {
    bg: 'bg-confidence-conflict/20',
    text: 'text-confidence-conflict',
    label: '⚠ CONFLICT',
  },
};

export default function ConfidenceBadge({ confidence }: ConfidenceBadgeProps) {
  const config = BADGE_CONFIG[confidence];

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold ${config.bg} ${config.text}`}
    >
      {config.label}
    </span>
  );
}
