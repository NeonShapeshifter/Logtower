/**
 * Color constants for the Logtower TUI
 * Centralized color definitions for consistent theming
 */

// Severity Colors
export const SEVERITY_COLORS = {
  CRITICAL: 'red',
  HIGH: 'magenta',
  MEDIUM: 'yellow',
  LOW: 'cyan',
  INFO: 'white',
} as const;

// Get color for a severity level
export function getSeverityColor(severity: string): string {
  return SEVERITY_COLORS[severity as keyof typeof SEVERITY_COLORS] || 'white';
}

// Status Colors
export const STATUS_COLORS = {
  ONLINE: 'green',
  OFFLINE: 'grey',
  CHECKING: 'yellow',
  RUNNING: 'green',
  STOPPED: 'red',
  SUCCESS: 'green',
  ERROR: 'red',
  WARNING: 'yellow',
} as const;

// Border Colors
export const BORDER_COLORS = {
  DEFAULT: 'white',
  PRIMARY: 'cyan',
  SECONDARY: 'grey',
  DANGER: 'red',
  SUCCESS: 'green',
  WARNING: 'yellow',
  INFO: 'blue',
  ACCENT: 'magenta',
} as const;

// Text Colors
export const TEXT_COLORS = {
  PRIMARY: 'white',
  SECONDARY: 'grey',
  COMMAND: 'green',
  HIGHLIGHT: 'cyan',
  DANGER: 'red',
  WARNING: 'yellow',
} as const;

// Component-specific colors
export const COMPONENT_COLORS = {
  // SplitView
  EVENT_STREAM_BORDER: 'blue',
  LOG_DETAIL_BORDER: 'grey',
  RADAR_BORDER_ACTIVE: 'red',
  RADAR_BORDER_IDLE: 'green',
  INSPECTOR_BORDER: 'yellow',
  CRITICAL_QUEUE_BORDER: 'red',

  // LateralView
  LATERAL_HEADER_BORDER: 'magenta',
  TABLE_HEADER_BORDER: 'cyan',
  TABLE_ROW_BORDER: 'grey',
  LINK_SUCCESS: 'green',
  LINK_FAILED: 'red',

  // Pokedex
  RULE_CATALOG_BORDER: 'blue',
  RULE_DETAIL_HEADER: 'cyan',
  RULE_DETAIL_BODY: 'white',
} as const;

// Severity order for sorting (lower = higher priority)
export const SEVERITY_ORDER = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
} as const;
