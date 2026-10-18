#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -P "$(dirname "$0")/.." && pwd)
cd "$repo_root"
export ENIGMA_CASE_A_TIMING=1
exec cargo test --release --locked -p enigma-cli --test bomm_parity historical_m4_u264_attack_board -- --ignored --exact --nocapture
