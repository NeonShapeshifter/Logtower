#!/usr/bin/env node
import React from 'react';
import { render } from 'ink';
import { App } from './ui/App.js';
import { Command } from 'commander';
import fs from 'fs';
import { runHeadless } from './headless.js';
import { createRequire } from 'module';
import updateNotifier from 'update-notifier';

const require = createRequire(import.meta.url);
const pkg = require('../package.json');

updateNotifier({ pkg }).notify();

const program = new Command();

program
  .name('logtower')
  .description('Logtower TUI and Headless CLI')
  .version(pkg.version)
  .option('--ruleset <name>', 'Ruleset to use (lolbas, discovery, lateral, defense, cred, all)', 'all')
  .action((options) => {
      // Default action (no command): Launch TUI
      render(React.createElement(App, {
          ruleset: options.ruleset || 'all'
      }));
  });

program
  .command('hunt')
  .description('Run detection (headless with --json/--report/--summary, TUI otherwise)')
  .argument('<file>', 'Path to EVTX or JSONL file')
  .option('--ruleset <name>', 'Ruleset to use (lolbas, discovery, lateral, defense, cred, all)', 'all')
  .option('--report', 'Generate a summary report (headless)')
  .option('--summary', 'Generate a high-level summary report (headless)')
  .option('--filter <mode>', 'Filter for report (IMPORTANT or ALL)', 'IMPORTANT')
  .option('--json', 'Output findings as JSON (headless)')
  .option('--hours <number>', 'Analyze only the last N hours')
  .option('--limit <number>', 'Limit number of events processed')
  .option('--intel <path>', 'Path to intel feeds directory for IOC enrichment')
  .action(async (file, options) => {
    // Remove surrounding quotes if present (PowerShell/Windows may pass them)
    file = file.replace(/^["']|["']$/g, '');

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
        // Handle EVTX/JSON via Headless Mode
        // Note: runHeadless now supports JSON/JSONL too
        if (file.toLowerCase().endsWith('.evtx') || file.toLowerCase().endsWith('.json') || file.toLowerCase().endsWith('.jsonl')) {
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

        console.error("Error: Unsupported file format for headless mode. Use .evtx, .json, or .jsonl");
        process.exit(1);
    }

    // No output flags -> TUI with initialFile
    render(React.createElement(App, {
        ruleset: options.ruleset,
        initialFile: file
    }));
  });

// Execute Commander
program.parse();
