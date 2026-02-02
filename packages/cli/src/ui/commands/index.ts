/**
 * Commands module for Logtower TUI
 * Exports command handlers and dispatcher
 */

import fs from 'fs';
import { CommandContext, CommandResult } from './types.js';
import { runHunt } from './hunt.js';
import { runTrack } from './track.js';
import { runInfo } from './info.js';
import { COMMAND_ALIASES, COMMANDS } from '../constants/index.js';
import { ERROR_MESSAGES } from '../constants/messages.js';

export { CommandContext, CommandResult } from './types.js';
export { runHunt } from './hunt.js';
export { runTrack } from './track.js';
export { runInfo } from './info.js';

/**
 * Dispatch result from command execution
 */
export type DispatchResult = {
  handled: boolean;
  action?: 'exit' | 'help' | 'clear';
  error?: string;
};

/**
 * Dispatch a command to the appropriate handler
 * Returns action to be taken by the App component
 */
export function dispatchCommand(
  rawInput: string,
  ctx: CommandContext,
  exit: () => void
): DispatchResult {
  const parts = rawInput.trim().split(/\s+/);
  const rawCommand = parts[0].toLowerCase();
  const args = parts.slice(1);
  const command = COMMAND_ALIASES[rawCommand] || rawCommand;

  const { getState, setState, showError, goBackToSplash } = ctx;
  const state = getState();

  // Block commands if processing (except exit)
  if (state.isProcessing && command !== COMMANDS.EXIT) {
    return { handled: true };
  }

  switch (command) {
    case COMMANDS.EXIT:
      exit();
      return { handled: true, action: 'exit' };

    case COMMANDS.HELP:
      setState(prev => ({ ...prev, view: 'VIEW_HELP' }));
      return { handled: true, action: 'help' };

    case COMMANDS.CLEAR:
      goBackToSplash();
      return { handled: true, action: 'clear' };

    case COMMANDS.HUNT:
      if (args[0]) {
        if (!fs.existsSync(args[0])) {
          showError(ERROR_MESSAGES.FILE_NOT_FOUND(args[0]));
          return { handled: true, error: ERROR_MESSAGES.FILE_NOT_FOUND(args[0]) };
        }
        runHunt(args[0], ctx);
        return { handled: true };
      } else {
        showError(ERROR_MESSAGES.HUNT_USAGE);
        return { handled: true, error: ERROR_MESSAGES.HUNT_USAGE };
      }

    case COMMANDS.TRACK:
      runTrack(args[0], ctx);
      return { handled: true };

    case COMMANDS.INFO:
      runInfo(args.join(' ') || undefined, ctx);
      return { handled: true };

    default:
      if (rawCommand) {
        const errorMsg = ERROR_MESSAGES.UNKNOWN_COMMAND(rawCommand);
        showError(errorMsg);
        return { handled: true, error: errorMsg };
      }
      return { handled: false };
  }
}
