import { execSync } from 'child_process';

function runDetection(file) {
  try {
    const output = execSync(`node scripts/qa_runner.mjs ${file} --json --ruleset all`, { encoding: 'utf-8' });
    return JSON.parse(output);
  } catch (e) {
    console.error("Execution failed:", e.message);
    process.exit(1);
  }
}

const expectedRules = {
  'TOOL_003_PROCDUMP_LSASS': 1,
  'IMPACT_032_ESENTUTL_NTDS_CRITICAL': 1,
  'IMPACT_043_REG_RUNKEY_MOD_CMD': 1,
  'IMPACT_001_SHADOW_COPY_DELETE': 1,
  'IMPACT_041_RWINSTA_SESSION_RESET_MEDIUM': 1,
  'IMPACT_004_CIPHER_WIPE': 1
};

console.log("Running regression test on Impact rules...");

const findings = runDetection('datasets/synthetic/impact_regression.jsonl');
const findingMap = new Map();

for (const f of findings) {
  if (!findingMap.has(f.rule_id)) findingMap.set(f.rule_id, 0);
  findingMap.set(f.rule_id, findingMap.get(f.rule_id) + f.evidence.length);
}

let failed = false;

console.log("=== Impact Regression Results ===");
for (const [ruleId, minCount] of Object.entries(expectedRules)) {
  const actual = findingMap.get(ruleId) || 0;
  if (actual < minCount) {
    console.error(`FAIL: ${ruleId} expected >= ${minCount}, got ${actual}`);
    failed = true;
  } else {
    console.log(`PASS: ${ruleId} (Count: ${actual})`);
  }
}

if (failed) process.exit(1);
console.log("SUCCESS: Impact rules validated.");
