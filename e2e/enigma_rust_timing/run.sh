#!/bin/sh
# Times design A through the release enigma CLI and writes a new results file.
# Usage: [ENIGMA_TIMING_RUNS=N] e2e/enigma_rust_timing/run.sh   (default N: 100)
set -eu

script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
repo_root=$(CDPATH= cd -P "$script_dir/../.." && pwd)
cd "$repo_root"

cargo build --release --locked -p enigma-cli --bin enigma
binary=${CARGO_TARGET_DIR:-$repo_root/target}/release/enigma

timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
results=$script_dir/results
output=$results/$(printf '%s' "$timestamp" | tr -d ':-')-$(git rev-parse --short HEAD).json
mkdir -p "$results"
if [ -e "$output" ]; then
    echo "run.sh: $output already exists; not overwriting" >&2
    exit 1
fi

ENIGMA_TIMING_OUTPUT=$output
ENIGMA_TIMING_GIT_COMMIT=$(git rev-parse HEAD)
ENIGMA_TIMING_TIMESTAMP=$timestamp
ENIGMA_TIMING_BINARY=$binary
ENIGMA_TIMING_BINARY_SHA256=$(sha256sum "$binary" | cut -d ' ' -f 1)
export ENIGMA_TIMING_OUTPUT ENIGMA_TIMING_GIT_COMMIT ENIGMA_TIMING_TIMESTAMP
export ENIGMA_TIMING_BINARY ENIGMA_TIMING_BINARY_SHA256
exec cargo test --release --locked -p enigma-cli --test case_a_timing enigma_rust_case_a_timing -- --ignored --exact --nocapture
