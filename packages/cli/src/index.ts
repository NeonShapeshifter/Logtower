#!/usr/bin/env node
import React from 'react';
import { render } from 'ink';
import { App } from './ui/App.js';
import { Command } from 'commander';
import fs from 'fs';
import readline from 'readline';
import { DetectionEngine } from '@neonshapeshifter/logtower-engine';
import { BASE_RULES, RULESETS } from '@neonshapeshifter/logtower-rules';
import { runHeadless } from './headless.js';
import { normalizeEvent } from '@neonshapeshifter/logtower-core';
import { createRequire } from 'module';
import updateNotifier from 'update-notifier';

const require = createRequire(import.meta.url);
const pkg = require('../package.json');

updateNotifier({ pkg }).notify();

const program = new Command();

program
  .name('logtower')
  .description('Logtower TUI and Headless CLI')
  .version('0.0.1');

program
  .command('hunt')
  .description('Run detection (headless with --json/--report/--summary, TUI otherwise)')
  .argument('<file>', 'Path to EVTX or JSONL file')
  .option('--ruleset <name>', 'Ruleset to use (lolbas, discovery, lateral, defense, cred, all)', 'lolbas')
  .option('--report', 'Generate a summary report (headless)')
  .option('--summary', 'Generate a high-level summary report (headless)')
  .option('--filter <mode>', 'Filter for report (IMPORTANT or ALL)', 'IMPORTANT')
  .option('--json', 'Output findings as JSON (headless)')
  .option('--hours <number>', 'Analyze only the last N hours')
  .option('--limit <number>', 'Limit number of events processed')
  .option('--intel <path>', 'Path to intel feeds directory for IOC enrichment')
  .action(async (file, options) => {
    if (!fs.existsSync(file)) {
        if (options.json) console.log(JSON.stringify({ error: "File not found", path: file }));
        else console.error(`Error: File not found: ${file}`);
        process.exit(1);
    }

    if (fs.statSync(file).isDirectory()) {
        if (options.json) console.log(JSON.stringify({ error: "Path is a directory", path: file }));
        else console.error(`Error: Path is a directory: ${file}`);
        process.exit(1);
    }

    // If output flags present -> headless mode
    const isHeadless = options.json || options.report || options.summary;

    if (isHeadless) {
        // Handle EVTX via Headless Mode
        if (file.toLowerCase().endsWith('.evtx')) {
            const filterMode = options.filter === 'ALL' ? 'ALL' : 'IMPORTANT';
            const hours = options.hours ? parseFloat(options.hours) : undefined;
            const limit = options.limit ? parseInt(options.limit) : undefined;

            let intelPath = options.intel;
            if (!intelPath) {
                if (fs.existsSync('./feeds')) intelPath = './feeds';
                else if (fs.existsSync('./datasets/intel')) intelPath = './datasets/intel';
                if (intelPath && !options.json) console.log(`Auto-detected Intel Feeds at: ${intelPath}`);
            }

            runHeadless(file, filterMode, options.ruleset, options.json, options.summary, hours, limit, intelPath);
            return;
        }

        // Handle JSONL (Legacy/Debug stream)
        let rules = BASE_RULES;
        if (options.ruleset) {
            if (options.ruleset === 'all') {
                rules = RULESETS.all;
            } else if (RULESETS[options.ruleset as keyof typeof RULESETS]) {
                rules = RULESETS[options.ruleset as keyof typeof RULESETS];
            } else {
                console.error(`Error: Unknown ruleset '${options.ruleset}'. Available: ${Object.keys(RULESETS).join(', ')}, all`);
                process.exit(1);
            }
        }

        const engine = new DetectionEngine(rules);
        const fileStream = fs.createReadStream(file);
        const rl = readline.createInterface({
            input: fileStream,
            crlfDelay: Infinity
        });

        const cutoffTime = options.hours ? Date.now() - (parseFloat(options.hours) * 3600000) : 0;
        const limitCount = options.limit ? parseInt(options.limit) : Infinity;

        if (!options.json) {
            console.log(`Running detection on ${file} using ruleset: ${options.ruleset}...`);
            if (options.hours) console.log(`Time Filter: Last ${options.hours} hours`);
            if (options.limit) console.log(`Event Limit: ${options.limit}`);
        }

        let count = 0;
        for await (const line of rl) {
            if (!line.trim()) continue;
            try {
                const raw = JSON.parse(line);
                const event = normalizeEvent(raw);
                if (!event) continue;

                if (cutoffTime > 0 && event.timestamp) {
                    const eventTs = new Date(event.timestamp).getTime();
                    if (eventTs < cutoffTime) continue;
                }

                engine.processEvent(event);
                count++;

                if (count >= limitCount) break;
            } catch (e) {}
        }

        const findings = engine.getFindings();

        if (options.json) {
            console.log(JSON.stringify(findings, null, 2));
        } else {
            console.log(`\n=== Detection Report ===`);
            if (findings.length === 0) {
                console.log("No findings.");
            }
            for (const finding of findings) {
                console.log(`[ALERT] [${finding.id}] ${finding.rule_id}: ${finding.title}`);
                console.log(`Severity: ${finding.severity} | Evidence Count: ${finding.evidence.length}`);
                const lastEv = finding.evidence[finding.evidence.length - 1];
                console.log(`Sample Evidence: ${lastEv.summary}`);
                console.log(`-`.repeat(40));
            }
            console.log(`Processed ${count} events.`);
        }
        return;
    }

    // No output flags -> TUI with initialFile
    render(React.createElement(App, {
        ruleset: options.ruleset,
        initialFile: file
    }));
  });

import { resolveRuntimeConfig } from './args.js';

// Parse arguments
const config = resolveRuntimeConfig(process.argv);

// If ruleset is invalid in TUI mode, we might want to warn, but for now we proceed with fallback (lolbas)
// The resolver handles fallback internally.

if (config.mode === 'tui') {
    // Boot TUI directly with config
    render(React.createElement(App, { ruleset: config.ruleset }));
} else {
    // CLI Mode: Execute Commander
    program.parse();
}