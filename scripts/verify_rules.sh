#!/bin/bash
set -e

echo "Running Synthetic Regression Tests..."
OUTPUT=$(node scripts/qa_runner.mjs datasets/synthetic/lolbas_gaps.jsonl)

# Check for Rule IDs
echo "$OUTPUT" | grep -q "LOLBAS_012_INSTALLUTIL" && echo "PASS: LOLBAS_012" || (echo "FAIL: LOLBAS_012"; exit 1)
echo "$OUTPUT" | grep -q "LOLBAS_013_REGASM_REGSVCS" && echo "PASS: LOLBAS_013" || (echo "FAIL: LOLBAS_013"; exit 1)
echo "$OUTPUT" | grep -q "LOLBAS_010_WSCRIPT" && echo "PASS: LOLBAS_010" || (echo "FAIL: LOLBAS_010"; exit 1)

echo "All synthetic tests passed."
