import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const pkg = require('../../../package.json');

const VERSION = `v${pkg.version}`;

/**
 * User-facing message strings for the Logtower TUI
 * Centralized strings for consistent messaging and easy i18n
 */

// Application info
export const APP_INFO = {
  NAME: 'LOGTOWER',
  VERSION: VERSION,
  TAGLINE: 'High-Performance Forensics Suite',
  VERSION_LABEL: `${VERSION} (Rust Engine Enabled)`,
  HEADER_TITLE: `HEADER: Logtower ${VERSION}`,
} as const;

// Error messages
export const ERROR_MESSAGES = {
  FILE_NOT_FOUND: (file: string) => `File not found: ${file}`,
  NO_FILE_SPECIFIED: 'No file specified. Run hunt first or: track <file.evtx>',
  HUNT_USAGE: 'Usage: hunt <file.evtx>',
  UNKNOWN_COMMAND: (cmd: string) => `Unknown command: ${cmd}. Type 'help' for available commands.`,
  NO_RULES_FOUND: (query: string) => `No rules found matching "${query}"`,
} as const;

// Status messages
export const STATUS_MESSAGES = {
  SCANNING: '... scanning ...',
  WAITING_LOGS: 'Waiting for logs...',
  WAITING_DETECTIONS: 'Waiting for detections...',
  NO_CRITICAL_THREATS: 'No critical threats detected.',
  NO_LATERAL_MOVEMENT: 'No lateral movement detected.',
  NO_MOVEMENTS_DISPLAY: 'No movements to display.',
  PROCESSING_CANCEL: 'Run in progress — Ctrl+C to cancel',
  INTEL_CHECKING: 'checking...',
  INTEL_ONLINE: 'ONLINE',
  INTEL_OFFLINE: 'OFFLINE',
  INTEL_OFF: '[Intel: OFF]',
} as const;

// Labels
export const LABELS = {
  // Severity short labels
  SEVERITY_SHORT: {
    CRITICAL: '[CRIT]',
    HIGH: '[HIGH]',
    MEDIUM: '[MED]',
    LOW: '[LOW]',
    INFO: '[INFO]',
  },

  // Panel headers
  EVENT_STREAM: 'EVENT STREAM (45%)',
  LOG_DETAIL: '(Detalle del Log)',
  RADAR_ACTIVE: (ruleset: string) => `RADAR (40%) [${ruleset.toUpperCase()}]`,
  RADAR_REPORT: '=== Detection Report ===',
  INSPECTOR: 'INSPECTOR (55%)',
  CRITICAL_FINDINGS: (count: number) => `[!] CRITICAL FINDINGS (${count})`,
  LATERAL_SCOUT: 'LATERAL MOVEMENT SCOUT',
  RULE_CATALOG: (count: number) => `[RULE CATALOG] ${count} detection rules`,

  // Stats
  STATS_LINE: 'CRIT:{critical} | HIGH:{high} | MED:{medium} | LOW:{low}',

  // Summaries
  TOP_SEVERITY: 'Top 5 Severity',
  TOP_VOLUME: 'Top 5 Volume',

  // Alert indicators
  CRITICAL_ALERT: (count: number) => `[!] CRITICAL: ${count} threats detected`,
  OK_STATUS: '[OK] No critical threats',

  // Intel labels
  INTEL_MATCH: '[INTEL]',
  CRIT_LABEL: '[CRIT]',
} as const;

// Command descriptions
export const COMMAND_DESCRIPTIONS = {
  HUNT: 'Run detection on EVTX/JSONL files',
  HUNT_FULL: 'Run detection engine against a target file.',
  TRACK: 'Visualize lateral movement graph',
  TRACK_FULL: 'Build a lateral movement graph from logons.',
  INFO: 'Search rule catalog',
  INFO_FULL: 'Search detection rules by name/tag.',
  HELP: 'Show expanded help & examples',
  HELP_FULL: 'Show this help screen.',
  CLEAR: 'Return to splash screen',
  EXIT: 'Quit application',
} as const;

// Help text
export const HELP_TEXT = {
  COMMANDS_TITLE: 'LOGTOWER COMMAND REFERENCE',
  AVAILABLE_COMMANDS: 'CORE COMMANDS',
  ANALYSIS_SECTION: 'Analysis & Hunting:',
  NAVIGATION_SECTION: 'System:',
  CONTROLS_SECTION: 'Shortcuts:',

  // Keyboard shortcuts
  SHORTCUTS: {
    ESC_BACK: 'ESC / Q          Return to splash',
    TAB_TOGGLE: 'TAB              Toggle REPL visibility',
    CTRL_C: 'Ctrl+C           Cancel operation',
    ARROWS: '↑/↓ Select | Enter: Details | ESC: Exit',
    TAB_VIEW: 'TAB: Switch View | q: Quit',
    NAV_MODE: 'TAB: Nav Mode | Ctrl+C: cancel',
    WRITE_MODE: 'TAB: Write Mode | Esc/q: back | f: filter | s: summary',
    PGUP_PGDN: (offset: number, max: number) => `${offset}/${max} (PgUp/PgDn)`,
  },

  // Tips
  TIP_TITLE: '[PRO TIP]',
  TIP_TAB: "Try 'hunt evidence.evtx --ruleset lateral' for focused analysis.",
  TIP_ESC: "Type 'help' to see advanced flags and usage examples.",
  RETURN_HINT: 'Press ESC or Q to return',
  RETURN_TO_MENU: 'Press ESC or Q to return to menu.',
  RETURN_TO_LIST: "Press 'q' or 'ESC' to return to list.",
} as const;

// Inspector section headers
export const INSPECTOR_HEADERS = {
  THREAT_INTEL: '[THREAT INTEL MATCH]',
  WMI_PERSISTENCE: '[WMI PERSISTENCE]',
  AD_CHANGE: '[AD DIRECTORY CHANGE]',
  PROCESS_INJECTION: '[PROCESS INJECTION / ACCESS]',
  BITS_JOB: '[BITS JOB]',
  REGISTRY_EVENT: '[REGISTRY EVENT]',
  SERVICE_INSTALL: '[SERVICE INSTALLATION]',
  DLL_SIDELOAD: '[DLL SIDELOADING]',
  PROCESS_EXEC: '[PROCESS EXECUTION]',
  SCHEDULED_TASK: '[SCHEDULED TASK]',
  DESCRIPTION: '[DESCRIPTION]',
  EVIDENCE: (count: number) => `[RECENT EVIDENCE (${count})]`,
  MITRE: '[MITRE]:',
} as const;

// Pokedex messages
export const POKEDEX_MESSAGES = {
  DESCRIPTION_FALLBACK: 'No tactical description available for this threat.',
  RESPONSE_FALLBACK: [
    '1. TRIAGE: Validate if the activity is authorized.',
    '2. ISOLATE: If unauthorized, isolate the host.',
    '3. INVESTIGATE: Review process tree and parent processes.',
  ],
  SECTION_DESCRIPTION: 'DESCRIPTION:',
  SECTION_METADATA: 'METADATA',
  SECTION_DETECTION: 'DETECTED BY (Logic):',
  SECTION_RESPONSE: 'RESPONSE (The Protocol):',
} as const;

// REPL prompts
export const REPL = {
  PROMPT: 'logtower> ',
  PLACEHOLDER_PROCESSING: 'Run in progress — Ctrl+C to cancel',
  PLACEHOLDER_DEFAULT: "Type 'help' or 'hunt <file>'",
} as const;

// Footer messages
export const FOOTER = {
  PROCESSED: (count: number, visible: number, total: number) =>
    `Processed: ${count} events | Visible: ${visible} / Total: ${total}`,
  STATUS_RUNNING: 'RUNNING',
  STATUS_STOPPED: 'STOPPED (report mode)',
} as const;

// Filter messages
export const FILTER_MESSAGES = {
  HIDDEN_COUNT: (count: number) => `(${count} hidden - press 'f' to see ALL)`,
  NO_FINDINGS_IN_VIEW: (mode: string) => `No findings in ${mode} view. Press 'f' to toggle.`,
} as const;
