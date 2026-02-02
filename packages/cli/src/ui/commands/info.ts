/**
 * Info command - Browse and search detection rules
 * Extracted from App.tsx for modularity
 */

import { RULESETS } from '@neonshapeshifter/logtower-rules';
import { CommandContext, CommandResult } from './types.js';
import { ERROR_MESSAGES } from '../constants/index.js';

/**
 * Execute the info command
 * Searches and displays detection rules
 */
export function runInfo(
  query: string | undefined,
  ctx: CommandContext
): CommandResult {
  const { setState, showError } = ctx;

  const allRules = RULESETS.all;

  const matches = query
    ? allRules.filter(r =>
        r.id.toLowerCase().includes(query.toLowerCase()) ||
        r.title.toLowerCase().includes(query.toLowerCase()) ||
        r.mitre?.some((m: string) => m.toLowerCase().includes(query.toLowerCase()))
      )
    : allRules;

  if (matches.length === 0) {
    const errorMsg = ERROR_MESSAGES.NO_RULES_FOUND(query || '');
    showError(errorMsg);
    return { success: false, error: errorMsg };
  }

  setState(prev => ({
    ...prev,
    view: 'VIEW_INFO',
    infoMatches: matches
  }));

  return { success: true };
}
