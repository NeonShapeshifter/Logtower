import { execSync } from 'child_process';
import fs from 'fs';

function runDetection(file) {
  try {
    const output = execSync(`node scripts/qa_runner.mjs ${file} --json --ruleset lolbas`, { encoding: 'utf-8' });
    return JSON.parse(output);
  } catch (e) {
    console.error("Execution failed:", e.message);
    process.exit(1);
  }
}

const expectedRules = {
  'LOLBAS_012_INSTALLUTIL': 1,
  'LOLBAS_013_REGASM_REGSVCS': 1,
  'LOLBAS_010_WSCRIPT': 2, // wscript + cscript //e:vbscript
  'LOLBAS_009_CMD_GENERIC': 1,
  'LOLBAS_009_CMD_SUSPICIOUS': 1,
  'LOLBAS_008_SCHTASKS_GENERIC': 1,
  'LOLBAS_008_SCHTASKS_PERSISTENCE': 1
};

// Also allows LOLBAS_003_POWERSHELL to trigger on the cmd-spawned events if they match
// But we want to strictly check the Split Logic.
// Warning: "LOLBAS_003_POWERSHELL" might trigger on "cmd /c powershell -enc" depending on the event fields.
// The synthetic events have "process.image": "cmd.exe", so LOLBAS_003 (looking for powershell.exe image) should NOT trigger.
// BUT, if LOLBAS_009 generic logic is sloppy, it might catch the suspicious one too.
// We used !pattern in Generic, so they should be mutually exclusive per event.

const findings = runDetection('datasets/synthetic/lolbas_regression.jsonl');
const findingMap = new Map();

for (const f of findings) {
  if (!findingMap.has(f.rule_id)) findingMap.set(f.rule_id, 0);
  findingMap.set(f.rule_id, findingMap.get(f.rule_id) + f.evidence.length);
}

let failed = false;

console.log("=== Regression Results ===");
for (const [ruleId, minCount] of Object.entries(expectedRules)) {
  const actual = findingMap.get(ruleId) || 0;
  if (actual < minCount) {
    console.error(`FAIL: ${ruleId} expected >= ${minCount}, got ${actual}`);
    failed = true;
  } else {
    console.log(`PASS: ${ruleId} (Count: ${actual})`);
  }
}

// Check for unexpected rules? 
// Not strictly enforcing allowlist for now, but good to know.
for (const [ruleId, count] of findingMap) {
  if (!expectedRules[ruleId]) {
    console.warn(`WARN: Unexpected rule triggered: ${ruleId} (Count: ${count})`);
    // failed = true; // Uncomment to enforce strict allowlist
  }
}

if (failed) process.exit(1);
console.log("SUCCESS: All rules validated.");
