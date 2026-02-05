
import { RULESETS } from '../packages/rules/dist/index.js';

const allRules = RULESETS.all;
const ids = new Map();
let dups = 0;

allRules.forEach(r => {
    if (ids.has(r.id)) {
        console.log(`DUPLICATE ID: ${r.id} (${r.title})`);
        dups++;
    }
    ids.set(r.id, true);
});

console.log(`Total rules: ${allRules.length}`);
console.log(`Duplicates found: ${dups}`);
