#!/bin/bash
set -e

# Configuration
SAMPLE="datasets/samples/smoke_sample.jsonl"
CLI_BIN="packages/cli/dist/index.js"
EXPECTED_RULE="LOLBAS_006_REGSVR32"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo "---------------------------------------------------"
echo "LOGTOWER CLI SMOKE TEST"
echo "---------------------------------------------------"

# 1. Ensure CLI is built
echo "Building CLI..."
npm run build --workspace=@neonshapeshifter/logtower > /dev/null

# 2. Run Headless Hunt
echo "Running hunt on sample: $(basename "$SAMPLE")"
# Capture output but also print it to stderr so user sees progress/errors if needed
# We filter stdout to a variable for checking
OUTPUT=$(node "$CLI_BIN" hunt "$SAMPLE" --report --filter ALL --ruleset lolbas)

# Print output for visibility
echo "$OUTPUT"
echo "---------------------------------------------------"

# 3. Validations

# Check 1: Processed count must NOT be 0
if echo "$OUTPUT" | grep -q "Processed: 0"; then
    echo -e "${RED}[FAIL] Processed events count is 0.${NC}"
    exit 1
fi

# Check 2: Processed count line exists (sanity check format)
if ! echo "$OUTPUT" | grep -q "Processed:"; then
    echo -e "${RED}[FAIL] Output malformed (missing 'Processed:' line).${NC}"
    exit 1
fi

# Check 3: Expected Rule ID
if echo "$OUTPUT" | grep -q "$EXPECTED_RULE"; then
    echo -e "${GREEN}[PASS] Found expected rule: $EXPECTED_RULE${NC}"
else
    echo -e "${RED}[FAIL] Missing expected rule: $EXPECTED_RULE${NC}"
    exit 1
fi

echo -e "${GREEN}[SUCCESS] All smoke tests passed.${NC}"
exit 0
