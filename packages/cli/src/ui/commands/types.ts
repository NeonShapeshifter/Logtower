/**
 * Command types for dependency injection
 * Allows commands to be decoupled from React state management
 */

import { AppState, IntelStatus, TrackGraph } from '../types/index.js';
import { LogtowerEvent, Finding } from '@neonshapeshifter/logtower-core';
import { Rule } from '@neonshapeshifter/logtower-engine';
import { ChildProcess } from 'child_process';

/**
 * Context provided to command handlers
 * Contains all dependencies needed to execute commands
 */
export type CommandContext = {
  // State access
  getState: () => AppState;
  setState: React.Dispatch<React.SetStateAction<AppState>>;

  // Actions
  showError: (msg: string) => void;
  goBackToSplash: () => void;

  // Configuration
  ruleset: string;
  repoRoot: string;
};

/**
 * Result of command execution
 */
export type CommandResult = {
  success: boolean;
  error?: string;
};

/**
 * Hunt command specific state updates
 */
export type HuntStateUpdate = {
  logs?: LogtowerEvent[];
  findings?: Finding[];
  processedCount?: number;
  isProcessing?: boolean;
  activeProcess?: ChildProcess;
  intelStatus?: IntelStatus;
  currentFile?: string;
  view?: 'VIEW_HUNT';
  activeEngines?: string[];
  replVisible?: boolean;
};

/**
 * Track command specific state updates
 */
export type TrackStateUpdate = {
  view?: 'VIEW_TRACK';
  trackGraph?: TrackGraph;
  isProcessing?: boolean;
};

/**
 * Info command specific state updates
 */
export type InfoStateUpdate = {
  view?: 'VIEW_INFO';
  infoMatches?: Rule[];
};
