#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build}"
GPU_ARCH="${GPU_ARCH:-gfx1100}"
CPU_PROVE_MAX="${CPU_PROVE_MAX:-25}"
WARMUP="${WARMUP:-0}"

MODE="${1:-correctness}"
K_MIN="${2:-20}"
K_MAX="${3:-27}"
REPEAT="${4:-3}"

die(){ echo "error: $*" >&2; exit 2; }
need(){ command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }

[[ "$MODE" == correctness || "$MODE" == performance || "$MODE" == all ]] || \
  die "usage: $0 correctness|performance|all [scale-min 20] [scale-max 27] [repeat 3]"
[[ "$K_MIN" =~ ^[0-9]+$ && "$K_MAX" =~ ^[0-9]+$ && "$REPEAT" =~ ^[0-9]+$ ]] || die "scale and repeat must be integers"
(( K_MIN >= 20 && K_MAX <= 27 && K_MIN <= K_MAX )) || die "scale range must be within 20..27"
(( REPEAT >= 1 )) || die "repeat must be >= 1"
if [[ "$MODE" != performance ]] && (( REPEAT < 2 )); then die "correctness repeat must be >= 2"; fi
[[ "$CPU_PROVE_MAX" =~ ^[0-9]+$ ]] || die "CPU_PROVE_MAX must be an integer"

mkdir -p "$BUILD/bin" "$BUILD/logs" "$BUILD/proofs" "$BUILD/reports"

CPP="$BUILD/bin/qingming-cpp"
RUST="$BUILD/bin/qingming-rust"
GPU="$BUILD/bin/qingming-rx7900xtx"
CONSTANTS="$ROOT/rx7900xtx-24g/qingming_poseidon2_g64_constants.h"
EXPECTED="$ROOT/benchmarks/expected.csv"

build_core(){
  need g++
  need rustc
  need hipcc
  echo "[build] C++ reference"
  g++ -O3 -std=c++20 "$ROOT/cpu-cpp/qingming_stark_g64.cpp" -o "$CPP"
  echo "[build] Rust reference"
  rustc -O "$ROOT/cpu-rust/qingming_stark_g64.rs" -o "$RUST"
  echo "[build] RX7900XTX canonical prover ($GPU_ARCH)"
  hipcc -O3 -std=c++20 --offload-arch="$GPU_ARCH" -x hip \
    "$ROOT/rx7900xtx-24g/qingming_stark_g64_rx7900xtx.hip" -o "$GPU"
}

build_air_examples(){
  echo "[build] AIR examples"
  g++ -O3 -std=c++20 "$ROOT/examples/fibonacci/fibonacci.cpp" -o "$BUILD/bin/fibonacci-cpp"
  rustc -O "$ROOT/examples/fibonacci/fibonacci.rs" -o "$BUILD/bin/fibonacci-rust"
  hipcc -O3 -std=c++20 --offload-arch="$GPU_ARCH" -x hip \
    "$ROOT/examples/fibonacci/fibonacci.hip" -o "$BUILD/bin/fibonacci-hip"

  g++ -O3 -std=c++20 "$ROOT/examples/poseidon2-chain/poseidon2_chain.cpp" -o "$BUILD/bin/poseidon2-chain-cpp"
  rustc -O "$ROOT/examples/poseidon2-chain/poseidon2_chain.rs" -o "$BUILD/bin/poseidon2-chain-rust"
  hipcc -O3 -std=c++20 --offload-arch="$GPU_ARCH" -x hip \
    "$ROOT/examples/poseidon2-chain/poseidon2_chain.hip" -o "$BUILD/bin/poseidon2-chain-hip"
}

value_from_log(){
  local key="$1" file="$2"
  awk -F= -v key="$key" '$1==key {print substr($0,index($0,"=")+1); exit}' "$file"
}

check_air_expected(){
  local air_id="$1" log="$2"
  local row
  row="$(awk -F, -v id="$air_id" '$1=="air" && $2==id {print; exit}' "$EXPECTED")"
  [[ -n "$row" ]] || die "missing expected AIR row for $air_id"
  local kind id fp o0 o1 o2 o3 root bytes fnv
  IFS=, read -r kind id fp o0 o1 o2 o3 root bytes fnv <<<"$row"
  [[ "$(value_from_log trace_fingerprint "$log")" == "$fp" ]] || die "$air_id fingerprint mismatch"
  [[ "$(value_from_log public_output_0 "$log")" == "$o0" ]] || die "$air_id output 0 mismatch"
  [[ "$(value_from_log public_output_1 "$log")" == "$o1" ]] || die "$air_id output 1 mismatch"
  if [[ -n "$o2" ]]; then [[ "$(value_from_log public_output_2 "$log")" == "$o2" ]] || die "$air_id output 2 mismatch"; fi
  if [[ -n "$o3" ]]; then [[ "$(value_from_log public_output_3 "$log")" == "$o3" ]] || die "$air_id output 3 mismatch"; fi
}

run_air_examples(){
  echo "[air] Fibonacci C++ / Rust / HIP"
  "$BUILD/bin/fibonacci-cpp" > "$BUILD/logs/fibonacci-cpp.log"
  "$BUILD/bin/fibonacci-rust" > "$BUILD/logs/fibonacci-rust.log"
  "$BUILD/bin/fibonacci-hip" > "$BUILD/logs/fibonacci-hip.log"
  sed '/^backend=/d' "$BUILD/logs/fibonacci-cpp.log" > "$BUILD/logs/fibonacci-cpp.normalized"
  sed '/^backend=/d' "$BUILD/logs/fibonacci-rust.log" > "$BUILD/logs/fibonacci-rust.normalized"
  sed '/^backend=/d' "$BUILD/logs/fibonacci-hip.log" > "$BUILD/logs/fibonacci-hip.normalized"
  cmp "$BUILD/logs/fibonacci-cpp.normalized" "$BUILD/logs/fibonacci-rust.normalized"
  cmp "$BUILD/logs/fibonacci-cpp.normalized" "$BUILD/logs/fibonacci-hip.normalized"
  check_air_expected "QMG-AIR-FIBONACCI" "$BUILD/logs/fibonacci-cpp.log"

  echo "[air] Poseidon2 chain C++ / Rust / HIP"
  "$BUILD/bin/poseidon2-chain-cpp" > "$BUILD/logs/poseidon2-chain-cpp.log"
  "$BUILD/bin/poseidon2-chain-rust" > "$BUILD/logs/poseidon2-chain-rust.log"
  "$BUILD/bin/poseidon2-chain-hip" > "$BUILD/logs/poseidon2-chain-hip.log"
  sed '/^backend=/d' "$BUILD/logs/poseidon2-chain-cpp.log" > "$BUILD/logs/poseidon2-chain-cpp.normalized"
  sed '/^backend=/d' "$BUILD/logs/poseidon2-chain-rust.log" > "$BUILD/logs/poseidon2-chain-rust.normalized"
  sed '/^backend=/d' "$BUILD/logs/poseidon2-chain-hip.log" > "$BUILD/logs/poseidon2-chain-hip.normalized"
  cmp "$BUILD/logs/poseidon2-chain-cpp.normalized" "$BUILD/logs/poseidon2-chain-rust.normalized"
  cmp "$BUILD/logs/poseidon2-chain-cpp.normalized" "$BUILD/logs/poseidon2-chain-hip.normalized"
  check_air_expected "QMG-AIR-POSEIDON2-CHAIN" "$BUILD/logs/poseidon2-chain-cpp.log"
  echo "air_examples=PASS"
}

gpu_run_path(){
  local base="$1" run="$2" repeat="$3"
  if (( repeat > 1 )); then
    printf '%s.run-%s.qmg64p01\n' "${base%.qmg64p01}" "$run"
  else
    printf '%s\n' "$base"
  fi
}

check_scale20_expected(){
  local log="$1" row
  row="$(awk -F, '$1=="canonical" && $2=="20" {print; exit}' "$EXPECTED")"
  [[ -n "$row" ]] || die "missing canonical scale 20 expected row"
  local kind id fp o0 o1 o2 o3 root bytes fnv
  IFS=, read -r kind id fp o0 o1 o2 o3 root bytes fnv <<<"$row"
  [[ "$(value_from_log trace_root "$log")" == "$root" ]] || die "scale 20 trace root mismatch"
  [[ "$(value_from_log proof_bytes "$log")" == "$bytes" ]] || die "scale 20 proof size mismatch"
  [[ "$(value_from_log proof_fnv "$log")" == "$fnv" ]] || die "scale 20 proof FNV mismatch"
}

run_correctness(){
  echo "[correctness] CPU regressions"
  "$CPP" test
  "$CPP" scale-contract
  "$RUST" test
  "$RUST" scale-contract

  local report="$BUILD/reports/correctness-gpu-${K_MIN}-${K_MAX}.csv"
  rm -f "$report"
  local first_gpu_proof=""

  for k in $(seq "$K_MIN" "$K_MAX"); do
    echo "[correctness] Scale 2^$k"
    local cpp_proof="$BUILD/proofs/cpp-scale-$k.qmg64p01"
    local rust_proof="$BUILD/proofs/rust-scale-$k.qmg64p01"
    local gpu_base="$BUILD/proofs/gpu-scale-$k.qmg64p01"
    local cpp_log="$BUILD/logs/cpp-scale-$k.log"
    local rust_log="$BUILD/logs/rust-scale-$k.log"
    local gpu_log="$BUILD/logs/gpu-scale-$k.log"

    if (( k <= CPU_PROVE_MAX )); then
      "$CPP" proof-file "$k" "$cpp_proof" | tee "$cpp_log"
      "$RUST" proof-file "$k" "$rust_proof" | tee "$rust_log"
      cmp "$cpp_proof" "$rust_proof"
      if (( k == 20 )); then check_scale20_expected "$cpp_log"; fi
    fi

    rm -f "$gpu_base" "${gpu_base%.qmg64p01}".run-*.qmg64p01
    "$GPU" --scale "$k" --repeat "$REPEAT" --seed 7 \
      --constants "$CONSTANTS" --proof-out "$gpu_base" --report-out "$report" | tee "$gpu_log"

    local gpu_first
    gpu_first="$(gpu_run_path "$gpu_base" 1 "$REPEAT")"
    [[ -f "$gpu_first" ]] || die "GPU proof missing: $gpu_first"
    [[ -n "$first_gpu_proof" ]] || first_gpu_proof="$gpu_first"

    "$CPP" verify-file "$k" "$gpu_first"
    "$RUST" verify-file "$k" "$gpu_first"

    if (( k <= CPU_PROVE_MAX )); then
      cmp "$cpp_proof" "$gpu_first"
    fi

    for run in $(seq 2 "$REPEAT"); do
      cmp "$gpu_first" "$(gpu_run_path "$gpu_base" "$run" "$REPEAT")"
    done
  done

  echo "[correctness] Malformed proof rejection"
  local bad="$BUILD/proofs/tampered.qmg64p01"
  cp "$first_gpu_proof" "$bad"
  printf 'X' | dd of="$bad" bs=1 seek=0 count=1 conv=notrunc 2>/dev/null
  if "$CPP" verify-file "$K_MIN" "$bad" >/dev/null 2>&1; then die "C++ verifier accepted tampered proof"; fi
  if "$RUST" verify-file "$K_MIN" "$bad" >/dev/null 2>&1; then die "Rust verifier accepted tampered proof"; fi

  echo "correctness=PASS"
  echo "gpu_report=$report"
}

run_performance(){
  local report="$BUILD/reports/performance-gpu-${K_MIN}-${K_MAX}.csv"
  rm -f "$report"

  if [[ "$WARMUP" =~ ^[0-9]+$ ]] && (( WARMUP > 0 )); then
    echo "[performance] Warmup x$WARMUP at Scale 2^$K_MIN"
    "$GPU" --scale "$K_MIN" --repeat "$WARMUP" --seed 7 \
      --constants "$CONSTANTS" --proof-out "$BUILD/proofs/warmup.qmg64p01" --no-write >/dev/null
  fi

  for k in $(seq "$K_MIN" "$K_MAX"); do
    echo "[performance] Scale 2^$k x$REPEAT"
    "$GPU" --scale "$k" --repeat "$REPEAT" --seed 7 \
      --constants "$CONSTANTS" --proof-out "$BUILD/proofs/performance-scale-$k.qmg64p01" \
      --report-out "$report" --no-write
  done
  echo "performance=PASS"
  echo "performance_report=$report"
}

case "$MODE" in
  correctness)
    build_core
    build_air_examples
    run_air_examples
    run_correctness
    ;;
  performance)
    build_core
    run_performance
    ;;
  all)
    build_core
    build_air_examples
    run_air_examples
    run_correctness
    run_performance
    ;;
esac
