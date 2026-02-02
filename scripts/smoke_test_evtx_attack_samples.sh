#!/bin/bash

# Configuration
SEARCH_DIR="datasets/samples/EVTX-ATTACK-SAMPLES"
CLI_PATH="./packages/cli/dist/index.js"

# Stats
total_files=0
ok_files=0
fail_files=0

# Arrays for stats (associative arrays)
declare -A file_findings
declare -A file_times

echo "Starting smoke test on $SEARCH_DIR"
echo "---------------------------------------------------"

# Check if CLI exists
if [ ! -f "$CLI_PATH" ]; then
    echo "Error: CLI not found at $CLI_PATH"
    exit 1
fi

# Find all evtx files
# Handle paths with spaces by using -print0 and reading with null delimiter
while IFS= read -r -d '' file; do
    ((total_files++))
    
    # Relative path for cleaner output/keys
    # Use python if realpath is missing or weird, but realpath should be fine on linux
    rel_path=$(realpath --relative-to="$PWD" "$file")
    
    # Print progress (overwrite line to be less spammy if needed, but simple echo is safer for logs)
    # echo -n "Processing [$total_files]: $rel_path ... "
    
    start_time=$(date +%s%N)
    # Run CLI
    # We use a temp file for output to parse findings count
    tmp_out=$(mktemp)
    
    # Run command
    # Using 'node' explicitly
    # Redirect stderr to /dev/null to keep output clean, unless we want to capture errors
    node "$CLI_PATH" hunt "$file" --ruleset all --json > "$tmp_out" 2> /dev/null
    exit_code=$?
    end_time=$(date +%s%N)
    
    duration=$(( (end_time - start_time) / 1000000 )) # milliseconds
    
    if [ $exit_code -eq 0 ]; then
        # Check for JSON validity and count findings
        count=$(jq '. | length' "$tmp_out" 2>/dev/null)
        if [ $? -eq 0 ]; then
             echo "[$total_files] OK (${duration}ms, $count findings) - $rel_path"
             ((ok_files++))
             file_findings["$rel_path"]=$count
             file_times["$rel_path"]=$duration
        else
             echo "[$total_files] FAIL (Invalid JSON) - $rel_path"
             ((fail_files++))
        fi
    else
        echo "[$total_files] FAIL (Exit code $exit_code) - $rel_path"
        ((fail_files++))
    fi
    
    rm "$tmp_out"
    
done < <(find "$SEARCH_DIR" -type f -name "*.evtx" -print0)

echo "---------------------------------------------------"
echo "Summary:"
echo "Total files: $total_files"
echo "OK: $ok_files"
echo "Fail: $fail_files"

echo ""
echo "Top 10 Files with most findings:"
# Sort by findings desc
for k in "${!file_findings[@]}"; do
    echo "${file_findings[$k]} $k"
done | sort -rn | head -n 10

echo ""
echo "Top 10 Slowest files:"
# Sort by time desc
for k in "${!file_times[@]}"; do
    echo "${file_times[$k]} $k"
done | sort -rn | head -n 10
