#!/bin/sh
# Times U-264 through pinned bomm and writes a new results file.
# Usage: [ENIGMA_TIMING_CASE=a|positions|b] [ENIGMA_TIMING_RUNS=N]
#        [ENIGMA_TIMING_THREADS=1..256] e2e/bomm_timing/run.sh [BOMM_BIN]
# Defaults: case a, runs=100, threads=1.
# Initial B comparison: explicit threads=1 then 6, runs=3, sequentially.
# Run sequentially, never alongside the enigma-rust harness.
set -eu

# Normalize decimal input once so the filename and measured flag agree.
threads=${ENIGMA_TIMING_THREADS-1}
case $threads in
    ''|*[!0-9]*) threads=invalid ;;
esac
while [ "${threads#0}" != "$threads" ]; do threads=${threads#0}; done
if [ -z "$threads" ] || [ "${#threads}" -gt 3 ] || [ "$threads" = invalid ] || [ "$threads" -gt 256 ]; then
    echo 'run.sh: ENIGMA_TIMING_THREADS must be an integer from 1 to 256' >&2
    exit 1
fi
ENIGMA_TIMING_THREADS=$threads
export ENIGMA_TIMING_THREADS

bomm_bin=${1:-${BOMM_BIN:-}}
if [ -z "$bomm_bin" ]; then
    echo "run.sh: set BOMM_BIN or pass the pinned bomm binary as the first argument" >&2
    exit 1
fi
case $bomm_bin in
    /*) ;;
    *) bomm_bin=$PWD/$bomm_bin ;;
esac
if [ ! -f "$bomm_bin" ] || [ ! -x "$bomm_bin" ]; then
    echo "run.sh: $bomm_bin is not an executable file" >&2
    exit 1
fi

script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
repo_root=$(CDPATH= cd -P "$script_dir/../.." && pwd)
cd "$repo_root"

timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
results=$script_dir/results
case_suffix=
if [ "${ENIGMA_TIMING_CASE-}" = positions ]; then
    case_suffix=-positions
elif [ "${ENIGMA_TIMING_CASE-}" = b ]; then
    case_suffix=-b
fi
output=$results/$(printf '%s' "$timestamp" | tr -d ':-')-$(git rev-parse --short HEAD)$case_suffix-t$threads.json
mkdir -p "$results"
if [ -e "$output" ]; then
    echo "run.sh: $output already exists; not overwriting" >&2
    exit 1
fi

BOMM_BIN=$bomm_bin
ENIGMA_TIMING_OUTPUT=$output
ENIGMA_TIMING_GIT_COMMIT=$(git rev-parse HEAD)
ENIGMA_TIMING_TIMESTAMP=$timestamp
ENIGMA_TIMING_BINARY_SHA256=$(sha256sum "$bomm_bin" | cut -d ' ' -f 1)
export BOMM_BIN ENIGMA_TIMING_OUTPUT ENIGMA_TIMING_GIT_COMMIT ENIGMA_TIMING_TIMESTAMP
export ENIGMA_TIMING_BINARY_SHA256
exec cargo test --release --locked -p enigma-cli --test case_a_timing bomm_case_a_timing -- --ignored --exact --nocapture
