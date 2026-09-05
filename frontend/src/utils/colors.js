/**
 * Severity and risk tier color mapping.
 * Maps to Precision Instrument Design System tokens (index.css).
 */

export const TIER_COLORS = {
  critical: 'var(--sev-critical)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--sev-low)',
  clean: 'var(--sev-clean)',
  info: 'var(--sev-info)',
};

export const TIER_COLORS_RAW = {
  critical: '#F43F5E',
  high: '#FB923C',
  medium: '#FACC15',
  low: '#38BDF8',
  clean: '#34D399',
  info: '#94A3B8',
};

export function getTierFromScore(score) {
  if (score >= 75) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';
  return 'clean';
}

export function getTierColor(tier) {
  return TIER_COLORS[String(tier).toLowerCase()] || TIER_COLORS.info;
}

export function getTierColorRaw(tier) {
  return TIER_COLORS_RAW[String(tier).toLowerCase()] || TIER_COLORS_RAW.info;
}

export function getBarColor(score) {
  if (score >= 75) return TIER_COLORS_RAW.critical;
  if (score >= 50) return TIER_COLORS_RAW.high;
  if (score >= 25) return TIER_COLORS_RAW.medium;
  return TIER_COLORS_RAW.clean;
}
