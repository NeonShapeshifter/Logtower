/**
 * Hunt command - Analyzes EVTX files for threats
 * Extracted from App.tsx for modularity
 */

import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import { DetectionEngine, ThreatIntel } from '@neonshapeshifter/logtower-engine';
import { RULESETS } from '@neonshapeshifter/logtower-rules';
import { LogtowerEvent, normalizeEvent } from '@neonshapeshifter/logtower-core';
import { CommandContext, CommandResult } from './types.js';
import { BUFFER_LIMITS } from '../constants/index.js';
import { resolveParserBinary } from '../../utils.js';

/**
 * Execute the hunt command
 * Spawns Rust parser and processes events through detection engine
 */
export function runHunt(
  filePath: string,
  ctx: CommandContext
): CommandResult {
  const { getState, setState, ruleset, repoRoot } = ctx;
  const state = getState();

  // Safety: Kill any previous background process
  if (state.activeProcess) {
    state.activeProcess.kill();
  }

  // Select ruleset based on prop
  let rules = RULESETS.lolbas;
  if (ruleset === 'all') {
    rules = RULESETS.all;
  } else if (RULESETS[ruleset as keyof typeof RULESETS]) {
    rules = RULESETS[ruleset as keyof typeof RULESETS];
  }

  const engine = new DetectionEngine(rules);

  // Load Threat Intel (auto-detect feeds directory)
  const intel = new ThreatIntel();
  const feedsPath = path.join(repoRoot, 'feeds');
  let intelStats = { ips: 0, tor: 0, hashes: 0, domains: 0 };
  if (fs.existsSync(feedsPath)) {
    intelStats = intel.loadFromDirectory(feedsPath);
  }

  let rustParser: string;
  try {
      rustParser = resolveParserBinary();
  } catch (e: any) {
      return { success: false, error: e.message };
  }

  // Initialize state for hunt
  setState(prev => ({
    ...prev,
    view: 'VIEW_HUNT',
    currentFile: filePath,
    logs: [],
    findings: [],
    processedCount: 0,
    isProcessing: true,
    activeEngines: [ruleset],
    replVisible: false,
    intelStatus: { loaded: intel.isLoaded(), online: null, stats: intelStats }
  }));

  // Track domains for online checking (no local match)
  const pendingOnlineChecks = new Map<string, string>(); // domain -> findingId

  // Auto-detect online connectivity
  let isOnline = false;
  if (intel.isLoaded()) {
    intel.detectConnectivity().then(online => {
      isOnline = online;
      setState(prev => ({
        ...prev,
        intelStatus: { ...prev.intelStatus, online }
      }));
    });
  }

  try {
    const proc = spawn(rustParser, [filePath]);

    proc.stdout.on('data', (data) => {
      const lines = data.toString().split('\n');
      const newLogs: LogtowerEvent[] = [];

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const rawJson = JSON.parse(line);
          const event = normalizeEvent(rawJson);
          if (event) {
            // Check Intel on event
            if (intel.isLoaded()) {
              const intelMatch = intel.checkEvent(event);
              if (intelMatch) {
                (event as any)._intel = intelMatch;
              }
            }
            engine.processEvent(event);
            newLogs.push(event);
          }
        } catch (e) {
          // Skip malformed lines
        }
      }

      // Get findings and enrich with Intel
      const findings = engine.getFindings();
      if (intel.isLoaded()) {
        enrichFindingsWithIntel(findings, intel, pendingOnlineChecks);
      }

      // Batch update for performance
      setState(prev => ({
        ...prev,
        logs: [...prev.logs, ...newLogs].slice(-BUFFER_LIMITS.MAX_LOGS),
        findings: findings,
        processedCount: prev.processedCount + newLogs.length
      }));
    });

    proc.stderr.on('data', (_data) => {
      // Could log errors here if needed
    });

    proc.on('close', async (_code) => {
      // Online enrichment: check pending domains against URLhaus API
      if (isOnline && pendingOnlineChecks.size > 0) {
        const findings = engine.getFindings();
        for (const [domain, findingId] of pendingOnlineChecks) {
          const result = await intel.checkHostOnline(domain);
          if (result?.found) {
            const finding = findings.find(f => f.id === findingId);
            if (finding && !(finding as any).intel) {
              (finding as any).intel = {
                match: true,
                type: 'DOMAIN',
                value: domain,
                source: 'URLhaus API (Live)',
                description: result.threat || 'Malware Distribution'
              };
            }
          }
        }
        // Update state with enriched findings
        setState(prev => ({
          ...prev,
          findings: findings,
          isProcessing: false,
          activeProcess: undefined
        }));
      } else {
        setState(prev => ({
          ...prev,
          isProcessing: false,
          activeProcess: undefined
        }));
      }
    });

    // Save process ref
    setState(prev => ({ ...prev, activeProcess: proc }));

    return { success: true };

  } catch (e: any) {
    setState(prev => ({
      ...prev,
      view: 'VIEW_ERROR',
      errorMessage: e.message,
      isProcessing: false
    }));
    return { success: false, error: e.message };
  }
}

/**
 * Enrich findings with threat intelligence data
 */
function enrichFindingsWithIntel(
  findings: any[],
  intel: ThreatIntel,
  pendingOnlineChecks: Map<string, string>
): void {
  for (const finding of findings) {
    if ((finding as any).intel) continue; // Already enriched

    // Check IPs
    const srcIp = finding.evidence[0]?.raw_event?.IpAddress ||
                  finding.evidence[0]?.raw_event?.SourceIp;
    const dstIp = finding.evidence[0]?.raw_event?.DestinationIp;
    let match = intel.checkIp(srcIp) || intel.checkIp(dstIp);

    // Check domains in command line
    if (!match && finding.process?.command_line) {
      const urlPattern = /https?:\/\/([^\s/]+)/gi;
      let urlMatch;
      while ((urlMatch = urlPattern.exec(finding.process.command_line)) !== null) {
        const domain = urlMatch[1];
        match = intel.checkDomain(domain);
        if (match) break;
        // Queue for online check if no local match
        if (!pendingOnlineChecks.has(domain)) {
          pendingOnlineChecks.set(domain, finding.id);
        }
      }
    }

    if (match) {
      (finding as any).intel = {
        match: true,
        type: match.type,
        value: match.value,
        source: match.source,
        description: match.description
      };
    }
  }
}
