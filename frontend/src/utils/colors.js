/**
 * Severity and risk tier color mapping.
 */

export const TIER_COLORS = {
  critical: 'var(--crimson-alert)',
  high: 'var(--burnt-orange)',
  medium: 'var(--ochre-warn)',
  low: 'var(--sage-clear)',
  clean: 'var(--sage-clear)',
  info: 'var(--steel-info)',
};

export const TIER_COLORS_RAW = {
  critical: '#C94444',
  high: '#CC7832',
  medium: '#B89B3C',
  low: '#5B8A72',
  clean: '#5B8A72',
  info: '#6B7D93',
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
