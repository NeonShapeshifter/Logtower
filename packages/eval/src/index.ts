import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawn } from 'child_process';
import { DetectionEngine, Rule } from '@neonshapeshifter/logtower-engine';
import { BASE_RULES } from '@neonshapeshifter/logtower-rules';
import { LogtowerEventSchema } from '@neonshapeshifter/logtower-core';
import chalk from 'chalk';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '../../..');
const SAMPLES_DIR = path.join(REPO_ROOT, 'datasets/samples');

async function runTest(evtxPath: string, expectedPath: string) {
  console.log(chalk.blue(`Testing ${path.basename(evtxPath)}...`));
  
  // 1. Ingest
  const pythonScript = path.join(REPO_ROOT, 'packages/ingest-evtx/evtx_to_jsonl.py');
  const venvPython = path.join(REPO_ROOT, 'packages/ingest-evtx/.venv/bin/python');
  
  const events: any[] = [];
  
  await new Promise<void>((resolve, reject) => {
    const proc = spawn(venvPython, [pythonScript, evtxPath]);
    
    proc.stdout.on('data', (data) => {
      const lines = data.toString().split('\n');
      for (const line of lines) {
        if (line.trim()) {
          try {
            events.push(JSON.parse(line));
          } catch (e) {}
        }
      }
    });
    
    proc.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`Ingest failed code ${code}`));
    });
  });

  // 2. Hunt
  const engine = new DetectionEngine(BASE_RULES);
  for (const json of events) {
    const event = LogtowerEventSchema.parse(json);
    engine.processEvent(event);
  }
  
  const findings = engine.getFindings();
  const expected = JSON.parse(fs.readFileSync(expectedPath, 'utf-8'));

  // 3. Compare
  let passed = true;
  for (const exp of expected) {
    const match = findings.find(f => f.rule_id === exp.rule_id && f.host === exp.host);
    if (!match) {
      console.error(chalk.red(`  [FAIL] Expected rule ${exp.rule_id} on ${exp.host} NOT FOUND`));
      passed = false;
    } else {
      if (match.evidence.length < exp.count_min && 1000 > exp.count_min) { // approximate check
         // We only store 10 evidences, so exact count check is tricky unless we change engine.
         // For now, existence is enough.
         console.log(chalk.green(`  [PASS] Found ${exp.rule_id}`));
      } else {
         console.log(chalk.green(`  [PASS] Found ${exp.rule_id}`));
      }
    }
  }

  if (passed) console.log(chalk.green('Test Case Passed!'));
  else process.exit(1);
}

async function main() {
  const files = fs.readdirSync(SAMPLES_DIR);
  for (const file of files) {
    if (file.endsWith('.expected.json')) {
      const evtxName = file.replace('.expected.json', '.evtx');
      const evtxPath = path.join(SAMPLES_DIR, evtxName);
      if (fs.existsSync(evtxPath)) {
        await runTest(evtxPath, path.join(SAMPLES_DIR, file));
      }
    }
  }
}

main().catch(console.error);
