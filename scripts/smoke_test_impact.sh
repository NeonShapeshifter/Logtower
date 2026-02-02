#!/bin/bash
set -e

# Configuration
SAMPLE="synthetic_impact.jsonl"
CLI_BIN="packages/cli/dist/index.js"
EXPECTED_RULE="IMPACT_038_WEVTUTIL_CLEAR" 

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo "---------------------------------------------------"
echo "LOGTOWER CLI IMPACT SMOKE TEST (SYNTHETIC)"
echo "---------------------------------------------------"

# 1. Ensure CLI is built
echo "Building CLI..."
npm run build --workspace=@neonshapeshifter/logtower-cli > /dev/null

# 2. Run Headless Hunt
echo "Running hunt on sample: $(basename "$SAMPLE")"

# We use --ruleset impact
OUTPUT=$(node "$CLI_BIN" hunt "$SAMPLE" --report --filter ALL --ruleset impact)

# Print output for visibility
echo "$OUTPUT"
echo "---------------------------------------------------"

# 3. Validations
if echo "$OUTPUT" | grep -q "Processed: 0"; then
    echo -e "${RED}[FAIL] Processed events count is 0. Does CLI support JSONL?${NC}"
    exit 1
fi

if echo "$OUTPUT" | grep -q "IMPACT_"; then
    echo -e "${GREEN}[PASS] Found Impact rule detection.${NC}"
else
    echo -e "${RED}[FAIL] No Impact rule triggered on synthetic data.${NC}"
    exit 1
fi

echo -e "${GREEN}[SUCCESS] Impact Smoke test execution finished.${NC}"
exit 0
