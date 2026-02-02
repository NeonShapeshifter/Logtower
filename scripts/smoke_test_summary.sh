#!/bin/bash
set -e

REPO_ROOT=$(pwd)
CLI_PATH="$REPO_ROOT/packages/cli/dist/index.js"
SAMPLE_EVTX="$REPO_ROOT/datasets/samples/EVTX-ATTACK-SAMPLES/Defense Evasion/DE_1102_security_log_cleared.evtx"

echo "Running Summary Smoke Test..."

# 1. Text Summary
echo "[TEST 1] Text Summary"
OUTPUT_TEXT=$($CLI_PATH hunt "$SAMPLE_EVTX" --summary)

if echo "$OUTPUT_TEXT" | grep -q "=== Execution Summary ==="; then
    echo "PASS: Header found."
else
    echo "FAIL: Header missing."
    exit 1
fi

if echo "$OUTPUT_TEXT" | grep -q "Top 5 by Severity"; then
    echo "PASS: Top 5 Severity found."
else
    echo "FAIL: Top 5 Severity missing."
    exit 1
fi

if echo "$OUTPUT_TEXT" | grep -q "Top 5 by Count"; then
    echo "PASS: Top 5 Count found."
else
    echo "FAIL: Top 5 Count missing."
    exit 1
fi


# 2. JSON Summary
echo "[TEST 2] JSON Summary"
OUTPUT_JSON=$($CLI_PATH hunt "$SAMPLE_EVTX" --summary --json)

# Check for valid JSON structure (simple grep check)
if echo "$OUTPUT_JSON" | grep -q '"top_severity": \['; then
    echo "PASS: JSON top_severity found."
else
    echo "FAIL: JSON top_severity missing."
    exit 1
fi

if echo "$OUTPUT_JSON" | grep -q '"top_count": \['; then
    echo "PASS: JSON top_count found."
else
    echo "FAIL: JSON top_count missing."
    exit 1
fi

echo "ALL SUMMARY TESTS PASSED."
