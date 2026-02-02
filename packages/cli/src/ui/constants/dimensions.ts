/**
 * Layout dimension constants for the Logtower TUI
 * Centralized dimensions for consistent layout
 */

// Default terminal dimensions (fallback)
export const DEFAULT_TERMINAL = {
  COLUMNS: 80,
  ROWS: 24,
} as const;

// Global layout
export const LAYOUT = {
  GLOBAL_HEADER_HEIGHT: 2,
  FOOTER_HEIGHT: 3,
  MIN_BODY_HEIGHT: 10,
  PADDING: 1,
} as const;

// SplitView panel proportions (as decimals)
export const SPLIT_VIEW_PROPORTIONS = {
  // Column widths
  LEFT_COLUMN: '45%',
  RIGHT_COLUMN: '55%',

  // Right panel heights (as proportion of body)
  INTEL_HEIGHT: 0.20,
  RADAR_HEIGHT: 0.35,
  // Inspector takes remaining space

  // Left panel heights (as proportion of body)
  STREAM_HEIGHT: 0.45,
  // Detail takes remaining space
} as const;

// Fixed widths for specific components
export const FIXED_WIDTHS = {
  // Splash screen
  SPLASH_COMMAND_BOX: 60,
  SPLASH_TIP_BOX: 60,

  // Pokedex
  RULE_DETAIL_BOX: 70,

  // LateralView
  LATERAL_STATS_WIDTH: 80,
  TABLE_COLUMN_USER: 20,
  TABLE_COLUMN_SOURCE: 25,
  TABLE_COLUMN_TARGETS: 30,
  TABLE_COLUMN_PROTOCOLS: 20,
} as const;

// Spacing
export const SPACING = {
  MARGIN_NONE: 0,
  MARGIN_SMALL: 1,
  MARGIN_MEDIUM: 2,
  PADDING_SMALL: 1,
} as const;

// Buffer limits
export const BUFFER_LIMITS = {
  MAX_LOGS: 1000,
  MAX_TRUNCATE_LENGTH: 200,
} as const;

// Calculate dynamic heights based on terminal size
export function calculateSplitViewHeights(rows: number) {
  const bodyHeight = Math.max(
    LAYOUT.MIN_BODY_HEIGHT,
    rows - LAYOUT.FOOTER_HEIGHT - LAYOUT.GLOBAL_HEADER_HEIGHT
  );

  // Right panel
  const intelHeight = Math.floor(bodyHeight * SPLIT_VIEW_PROPORTIONS.INTEL_HEIGHT);
  const radarHeight = Math.floor(bodyHeight * SPLIT_VIEW_PROPORTIONS.RADAR_HEIGHT);
  const inspectorHeight = bodyHeight - intelHeight - radarHeight - 2; // -2 for margins

  // Left panel
  const streamHeight = Math.floor(bodyHeight * SPLIT_VIEW_PROPORTIONS.STREAM_HEIGHT);
  const detailHeight = bodyHeight - streamHeight - 1;

  return {
    bodyHeight,
    intelHeight,
    radarHeight,
    inspectorHeight,
    streamHeight,
    detailHeight,
  };
}
