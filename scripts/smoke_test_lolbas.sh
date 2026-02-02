#!/bin/bash
set -e

# Use a known LOLBAS sample
SAMPLE="datasets/samples/EVTX-ATTACK-SAMPLES/Execution/exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx"

if [ -f "$SAMPLE" ]; then
  echo "Running Smoke Test (LOLBAS Default) on $SAMPLE..."
  
  # 1. Test Text Report (Default Ruleset = LOLBAS)
  OUTPUT=$(node packages/cli/dist/index.js hunt "$SAMPLE" --report --filter ALL)
  echo "$OUTPUT"
  
  # Check if it mentions "Ruleset: lolbas"
  if echo "$OUTPUT" | grep -q "Ruleset: lolbas"; then
    echo "PASS: Default ruleset is lolbas."
  else
    echo "FAIL: Default ruleset is NOT lolbas."
    exit 1
  fi

  # Check if it detects a LOLBAS rule
  if echo "$OUTPUT" | grep -q "LOLBAS_005_RUNDLL32"; then
    echo "PASS: Detected LOLBAS_005_RUNDLL32."
  else
    echo "FAIL: Did not detect LOLBAS_005_RUNDLL32."
    exit 1
  fi

  # 2. Test JSON Output
  echo "Testing --json output..."
  JSON_OUTPUT=$(node packages/cli/dist/index.js hunt "$SAMPLE" --json)
  
  # Simple validation: is it an array?
  if echo "$JSON_OUTPUT" | grep -q "^\["; then
     echo "PASS: JSON output detected."
  else
     echo "FAIL: Output is not JSON."
     echo "$JSON_OUTPUT"
     exit 1
  fi

else
  echo "SKIPPED: Real sample not found."
  exit 0
fi
