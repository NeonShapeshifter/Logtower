#!/bin/bash
set -e

# Configuration
SAMPLE="datasets/samples/EVTX-ATTACK-SAMPLES/Credential Access/babyshark_mimikatz_powershell.evtx"
CLI_BIN="packages/cli/dist/index.js"
EXPECTED_RULE="CRED_001_PS_MIMIKATZ_LOAD"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo "---------------------------------------------------"
echo "LOGTOWER CLI CRED SMOKE TEST"
echo "---------------------------------------------------"

# 1. Ensure CLI is built
echo "Building CLI..."
npm run build --workspace=@neonshapeshifter/logtower-cli > /dev/null

# 2. Run Headless Hunt
echo "Running hunt on sample: $(basename "$SAMPLE")"
OUTPUT=$(node "$CLI_BIN" hunt "$SAMPLE" --report --filter ALL --ruleset cred)

# Print output for visibility
echo "$OUTPUT"
echo "---------------------------------------------------"

# 3. Validations
# Check 1: Processed count must NOT be 0
if echo "$OUTPUT" | grep -q "Processed: 0"; then
    echo -e "${RED}[FAIL] Processed events count is 0.${NC}"
    exit 1
fi

# Check 2: Expected Rule ID
if echo "$OUTPUT" | grep -q "$EXPECTED_RULE"; then
    echo -e "${GREEN}[PASS] Found expected rule: $EXPECTED_RULE${NC}"
else
    echo -e "${RED}[FAIL] Missing expected rule: $EXPECTED_RULE${NC}"
    exit 1
fi

echo -e "${GREEN}[SUCCESS] CRED Smoke test execution finished.${NC}"
exit 0
