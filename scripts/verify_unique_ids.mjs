import { RULESETS } from '../packages/rules/dist/index.js';

console.log("Verifying Rule ID Uniqueness...");

const allRules = [];
// Flatten all rulesets
for (const [key, rules] of Object.entries(RULESETS)) {
    if (key === 'all') continue;
    console.log(`Loading ruleset: ${key} (${rules.length} rules)`);
    allRules.push(...rules);
}

const seenIds = new Set();
const duplicates = [];

for (const rule of allRules) {
    if (seenIds.has(rule.id)) {
        duplicates.push(rule.id);
    }
    seenIds.add(rule.id);
}

if (duplicates.length > 0) {
    console.error("\n[FAIL] Duplicate Rule IDs found:");
    duplicates.forEach(id => console.error(` - ${id}`));
    console.error(`\nTotal unique rules: ${seenIds.size}`);
    console.error(`Total duplicate entries: ${duplicates.length}`);
    process.exit(1);
}

console.log("\n[SUCCESS] All Rule IDs are unique.");
console.log(`Total rules checked: ${allRules.length}`);
