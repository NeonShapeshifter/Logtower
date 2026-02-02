/**
 * Track command - Lateral movement analysis
 * Extracted from App.tsx for modularity
 */

import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import { DetectionEngine, LateralTracker } from '@neonshapeshifter/logtower-engine';
import { RULESETS } from '@neonshapeshifter/logtower-rules';
import { normalizeEvent } from '@neonshapeshifter/logtower-core';
import { CommandContext, CommandResult } from './types.js';
import { ERROR_MESSAGES } from '../constants/index.js';

/**
 * Execute the track command
 * Analyzes lateral movement patterns in EVTX files
 */
export function runTrack(
  file: string | undefined,
  ctx: CommandContext
): CommandResult {
  const { getState, setState, showError, repoRoot } = ctx;
  const state = getState();

  const targetFile = file || state.currentFile;

  if (!targetFile) {
    showError(ERROR_MESSAGES.NO_FILE_SPECIFIED);
    return { success: false, error: ERROR_MESSAGES.NO_FILE_SPECIFIED };
  }

  if (!fs.existsSync(targetFile)) {
    const errorMsg = ERROR_MESSAGES.FILE_NOT_FOUND(targetFile);
    showError(errorMsg);
    return { success: false, error: errorMsg };
  }

  setState(prev => ({ ...prev, isProcessing: true }));

  const tracker = new LateralTracker();
  const allRules = RULESETS.all;
  const engine = new DetectionEngine(allRules);
  const rustParser = path.join(repoRoot, 'packages/parser-rust/target/release/logtower-parser');

  try {
    const proc = spawn(rustParser, [targetFile]);
    let buffer = '';

    proc.stdout.on('data', (data) => {
      buffer += data.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const event = normalizeEvent(JSON.parse(line));
          if (event) {
            tracker.processEvent(event);
            engine.processEvent(event);
          }
        } catch {
          // Skip malformed lines
        }
      }
    });

    proc.on('close', () => {
      tracker.enrichWithFindings(engine.getFindings());
      const graph = tracker.getGraph();
      setState(prev => ({
        ...prev,
        view: 'VIEW_TRACK',
        trackGraph: graph,
        isProcessing: false
      }));
    });

    return { success: true };

  } catch (e: any) {
    showError(e.message);
    setState(prev => ({ ...prev, isProcessing: false }));
    return { success: false, error: e.message };
  }
}
