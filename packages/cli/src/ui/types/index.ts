/**
 * Shared types for the Logtower TUI
 * Centralized type definitions to avoid duplication
 */

import { ChildProcess } from 'child_process';
import { LogtowerEvent, Finding } from '@neonshapeshifter/logtower-core';
import { Rule, GraphNode, GraphEdge } from '@neonshapeshifter/logtower-engine';

/**
 * Intel status for threat intelligence
 * Used in App.tsx, SplitView.tsx, IntelQueue.tsx
 */
export type IntelStatus = {
  loaded: boolean;
  online: boolean | null;
  stats: {
    ips: number;
    tor: number;
    hashes: number;
    domains: number;
  };
};

/**
 * Application views/screens
 */
export type AppView =
  | 'VIEW_SPLASH'
  | 'VIEW_HUNT'
  | 'VIEW_TRACK'
  | 'VIEW_INFO'
  | 'VIEW_HELP'
  | 'VIEW_ERROR';

/**
 * Track graph data structure
 */
export type TrackGraph = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: {
    hosts: number;
    ips: number;
    connections: number;
    uniqueUsers: number;
    timeWindow: string;
  };
};

/**
 * Main application state
 */
export type AppState = {
  view: AppView;
  logs: LogtowerEvent[];
  findings: Finding[];
  processedCount: number;
  isProcessing: boolean;
  activeEngines: string[];
  errorMessage?: string;
  activeProcess?: ChildProcess;
  replVisible: boolean;
  intelStatus: IntelStatus;
  currentFile?: string;
  trackGraph?: TrackGraph;
  infoMatches?: Rule[];
};

/**
 * App component props
 */
export type AppProps = {
  ruleset?: string;
  initialFile?: string;
};

/**
 * SplitView component props
 */
export type SplitViewProps = {
  logs: LogtowerEvent[];
  findings: Finding[];
  processedCount: number;
  isProcessing: boolean;
  activeEngines: string[];
  ruleset: string;
  onBack: () => void;
  onCancel: () => void;
  replVisible: boolean;
  onToggleRepl: () => void;
  intelStatus: IntelStatus;
};

/**
 * CriticalQueue component props
 */
export type CriticalQueueProps = {
  findings: Finding[];
  height: number;
  intelStatus: IntelStatus;
};

/**
 * LateralView component props
 */
export type LateralViewProps = {
  graph: TrackGraph;
  onBack: () => void;
};

/**
 * Pokedex component props
 */
export type PokedexProps = {
  matches: Rule[];
  onBack: () => void;
};

/**
 * ReplInput component props
 */
export type ReplInputProps = {
  onSubmit: (command: string) => void;
  isProcessing: boolean;
  visible: boolean;
};

/**
 * HuntSummary component props
 */
export type HuntSummaryProps = {
  stats: Record<string, number>;
  topSeverity: Finding[];
  topCount: Finding[];
};

/**
 * Initial state factory
 */
export const createInitialState = (): AppState => ({
  view: 'VIEW_SPLASH',
  logs: [],
  findings: [],
  processedCount: 0,
  isProcessing: false,
  activeEngines: [],
  replVisible: true,
  intelStatus: {
    loaded: false,
    online: null,
    stats: { ips: 0, tor: 0, hashes: 0, domains: 0 }
  }
});
