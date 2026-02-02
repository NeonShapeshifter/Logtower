/**
 * Command-related constants for the Logtower TUI
 * Aliases, command names, and related configuration
 */

// Command aliases (shorthand → full command)
export const COMMAND_ALIASES: Record<string, string> = {
  'q': 'exit',
  'h': 'help',
  '?': 'help',
  'cls': 'clear',
  'i': 'info',
};

// Command names
export const COMMANDS = {
  EXIT: 'exit',
  HELP: 'help',
  CLEAR: 'clear',
  HUNT: 'hunt',
  TRACK: 'track',
  INFO: 'info',
} as const;

// Default values
export const DEFAULTS = {
  RULESET: 'lolbas',
} as const;

// Resolve command alias to full command name
export function resolveCommand(input: string): string {
  const lower = input.toLowerCase();
  return COMMAND_ALIASES[lower] || lower;
}
