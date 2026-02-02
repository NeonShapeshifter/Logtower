#!/bin/bash
set -e

SAMPLE="datasets/samples/EVTX-ATTACK-SAMPLES/Lateral Movement/LM_typical_IIS_webshell_sysmon_1_10_traces.evtx"

if [ -f "$SAMPLE" ]; then
  echo "Running Smoke Test on $SAMPLE..."
  
  # Run CLI via node
  OUTPUT=$(node packages/cli/dist/index.js hunt "$SAMPLE" --ruleset discovery --report --filter ALL)
  echo "$OUTPUT"
  
  # Verify specific discovery rule
  if echo "$OUTPUT" | grep -q "DISCOVERY_002_NET"; then
    echo "PASS: Discovery Rule 002 triggered on real sample."
  else
    echo "FAIL: Discovery Rule 002 did not trigger."
    exit 1
  fi
else
  echo "SKIPPED: Real sample not found. Relying on regression tests."
  exit 0
fi