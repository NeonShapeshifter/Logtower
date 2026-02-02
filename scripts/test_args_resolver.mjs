import { resolveRuntimeConfig } from '../packages/cli/dist/args.js';

// Mock argv generator
const mockArgv = (args) => ['node', 'logtower', ...args.split(' ').filter(x => x)];

const tests = [
  {
    name: 'Default TUI',
    input: '',
    expect: { mode: 'tui', ruleset: 'lolbas', rulesetValid: true }
  },
  {
    name: 'TUI with Discovery Ruleset',
    input: '--ruleset discovery',
    expect: { mode: 'tui', ruleset: 'discovery', rulesetValid: true }
  },
  {
    name: 'TUI with ALL Ruleset',
    input: '--ruleset all',
    expect: { mode: 'tui', ruleset: 'all', rulesetValid: true }
  },
  {
    name: 'TUI with Invalid Ruleset',
    input: '--ruleset invalid',
    expect: { mode: 'tui', ruleset: 'lolbas', rulesetValid: false }
  },
  {
    name: 'CLI Hunt',
    input: 'hunt file.evtx',
    expect: { mode: 'cli', ruleset: 'lolbas', rulesetValid: true }
  },
  {
    name: 'CLI Hunt with Discovery',
    input: 'hunt file.evtx --ruleset discovery',
    expect: { mode: 'cli', ruleset: 'discovery', rulesetValid: true }
  },
  {
    name: 'CLI Help',
    input: '--help',
    expect: { mode: 'cli', ruleset: 'lolbas', rulesetValid: true }
  },
  {
    name: 'CLI Short Help',
    input: '-h',
    expect: { mode: 'cli', ruleset: 'lolbas', rulesetValid: true }
  }
];

let failed = 0;
console.log("Running Argument Resolver Tests...");

for (const t of tests) {
  const result = resolveRuntimeConfig(mockArgv(t.input));
  
  let pass = true;
  if (result.mode !== t.expect.mode) pass = false;
  if (result.ruleset !== t.expect.ruleset) pass = false;
  if (result.rulesetValid !== t.expect.rulesetValid) pass = false;

  if (!pass) {
    console.error(`FAIL: ${t.name}`);
    console.error(`  Input: ${t.input}`);
    console.error(`  Expected:`, t.expect);
    console.error(`  Got:`, result);
    failed++;
  } else {
    console.log(`PASS: ${t.name}`);
  }
}

if (failed) process.exit(1);
console.log("All tests passed.");
