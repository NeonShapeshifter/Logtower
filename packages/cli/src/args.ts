import { RULESETS } from '@neonshapeshifter/logtower-rules';

export type RuntimeMode = 'tui' | 'cli';

export interface RuntimeConfig {
  mode: RuntimeMode;
  ruleset: string;
  rulesetValid: boolean;
}

export function resolveRuntimeConfig(argv: string[]): RuntimeConfig {
  // 1. Determine Mode
  // CLI only if output flags are present (headless) or help/version flags.
  // Otherwise, default to TUI.
  const args = argv.slice(2); // Skip node and script path

  let mode: RuntimeMode = 'tui';

  // Flags that force headless mode
  const hasOutputFlag = args.includes('--json') ||
                        args.includes('--report') ||
                        args.includes('--summary');
  const hasHelpFlag = args.includes('--help') || args.includes('-h');
  const hasVersionFlag = args.includes('--version') || args.includes('-v');

  // CLI headless only with output flags or help/version
  if (hasOutputFlag || hasHelpFlag || hasVersionFlag) {
    mode = 'cli';
  }

  // 2. Determine Ruleset
  // Default to 'lolbas'
  let ruleset = 'lolbas';
  let rulesetValid = true;

  const rulesetIdx = args.indexOf('--ruleset');
  if (rulesetIdx !== -1 && args[rulesetIdx + 1]) {
    const candidate = args[rulesetIdx + 1];
    
    // Validate against available rulesets + 'all'
    const validKeys = [...Object.keys(RULESETS), 'all'];
    
    if (validKeys.includes(candidate)) {
        ruleset = candidate;
    } else {
        // Invalid ruleset requested
        // If CLI mode, let Commander handle validation/error usually, but here we pre-resolve.
        // If TUI mode, fallback to default and flag as invalid (so UI can show warning if needed).
        // For consistency, we keep 'lolbas' as fallback but mark invalid.
        rulesetValid = false;
        // In CLI mode, we might want to let the command handler fail, but for this pure function,
        // we return the safe fallback state.
    }
  }

  return { mode, ruleset, rulesetValid };
}
