import { execSync } from 'child_process';

function runDetection(file) {
  try {
    const output = execSync(`node scripts/qa_runner.mjs ${file} --json --ruleset discovery`, { encoding: 'utf-8' });
    return JSON.parse(output);
  } catch (e) {
    console.error("Execution failed:", e.message);
    process.exit(1);
  }
}

const expectedRules = {
  'DISCOVERY_001_WHOAMI': 1,
  'DISCOVERY_002_NET': 2,
  'DISCOVERY_003_SYSTEMINFO': 1,
  'DISCOVERY_004_TASKLIST': 1,
  'DISCOVERY_005_IPCONFIG': 1,
  'DISCOVERY_006_NLTEST': 1,
  'DISCOVERY_007_NETSTAT': 1,
  'DISCOVERY_008_QUSER': 1,
  'DISCOVERY_009_ARP': 1,
  'DISCOVERY_010_ROUTE': 1
};

console.log("Running regression test on " + Object.keys(expectedRules).length + " discovery rules...");

const findings = runDetection('datasets/synthetic/discovery_regression.jsonl');
const findingMap = new Map();

for (const f of findings) {
  if (!findingMap.has(f.rule_id)) findingMap.set(f.rule_id, 0);
  findingMap.set(f.rule_id, findingMap.get(f.rule_id) + f.evidence.length);
}

let failed = false;

console.log("=== Discovery Regression Results ===");
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
console.log("SUCCESS: All Discovery rules validated.");