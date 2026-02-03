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
  .version('0.0.1')
  .option('--ruleset <name>', 'Ruleset to use (lolbas, discovery, lateral, defense, cred, all)', 'lolbas')
  .action((options) => {
      // Default action: Launch TUI
      render(React.createElement(App, {
          ruleset: options.ruleset || 'lolbas'
      }));
  });

program
  .command('hunt')
// ... (keep existing hunt command logic) ...
  .action(async (file, options) => {
    // ... (keep existing action body) ...
  });

// Execute Commander
program.parse();