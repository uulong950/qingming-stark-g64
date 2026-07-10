# qingming-stark-g64

`qingming-stark-g64` is a reproducible Goldilocks STARK backend verified on AMD RX 7900 XTX 24GB.

License:

```text
Apache-2.0
```

It follows the Qingming-style principle:

```text
contract
deterministic protocol boundary
explicit proof file
standalone verification
```

## Official integration surface

The official integration surface is intentionally small:

```text
CLI prover
QSPG64 .qsp proof file
standalone verifier
```

Community integrations should wrap the CLI and exchange `.qsp` proof files.

See:

```text
docs/INTEGRATION_POLICY.md
```

## Verified backend

```text
backend: rx7900xtx-24g
device: AMD RX 7900 XTX 24GB
field: Goldilocks / G64
hash: QINGMING-POSEIDON2-G64
proof: QSPG64 full STARK proof
AIR: QINGMING-AIR-GEOCLOCK-G64
```

Other AMD GPUs may work, but this package only claims verification on RX 7900 XTX 24GB.

## cryptographic contract

### Field

```text
field: Goldilocks / G64
p = 2^64 - 2^32 + 1
encoding: canonical uint64
rule: no silent reduction
```

### Hash

```text
hash: QINGMING-POSEIDON2-G64

t = 12
rate = 8
capacity = 4
digest_len = 4

alpha = 7
RF = 8
RP = 22
```

Frozen parameter fingerprints:

```text
poseidon2_params_fingerprint:       0xad77784b434bb34c
poseidon2_test_vectors_fingerprint: 0xffdf9225a1834ebc
```

Poseidon2-G64 is used for Merkle hashing, transcript hashing, public input binding, statement binding, composition challenge derivation, FRI challenge derivation, query sampling, and verifier transcript checks.

## STARK contract

Current compiled AIR:

```text
QINGMING-AIR-GEOCLOCK-G64
```

Public input layout:

```text
public_inputs[0] = transition_ratio
```

Constraint:

```text
trace_next - transition_ratio * trace_current = 0
```

The AIR profile owns:

```text
trace generator
constraint evaluator
quotient evaluator
local verifier checks
air_id
public input layout
```

The backend owns:

```text
NTT
trace commitment
quotient commitment
Merkle openings
FRI commit-fold chain
QSPG64 proof file
standalone verifier
```

## Proof contract

A `.qsp` file is a full QSPG64 STARK proof.

It binds:

```text
public inputs
public input digest
statement digest
trace_root
trace openings
quotient_root
QMPG64 quotient-FRI proof core
local AIR verifier material
```

The standalone verifier checks:

```text
public_input_binding
statement_digest
trace_openings
quotient_fri_check
local_air_checks
quotient_relation_checks
```

A QMPG64 proof core alone is not a complete STARK proof. The complete proof boundary is QSPG64.

## Retained Merkle tree proving

`stark-prove` uses retained Merkle trees.

During the first trace commitment and quotient FRI pass, the backend keeps Merkle trees in GPU memory. Opening extraction then reads paths from retained trees instead of rebuilding trees.

Expected proof-builder line:

```text
opening_source: retained_merkle_trees
```

This trades GPU memory for proof time.

## Build

```bash
make -C rx7900xtx-24g
```

## Minimal correctness check

```bash
./rx7900xtx-24g/build/qingming_stark_g64_backend \
  rx7900xtx-24g/include/qingming_poseidon2_g64_constants.h \
  --mode stark-check \
  --leaves 4096 \
  --cols 16 \
  --final-rows 1
```

Expected:

```text
status: PASS
local_air_checks: PASS
quotient_relation_checks: PASS
qmpg64v1_cpu_gpu_fri_check: PASS
```

## Full proof and standalone verification

Generate proof:

```bash
./rx7900xtx-24g/build/qingming_stark_g64_backend \
  rx7900xtx-24g/include/qingming_poseidon2_g64_constants.h \
  --mode stark-prove \
  --scale 27 \
  --cols 16 \
  --final-rows 1 \
  --proof-out geoclock_scale27.qsp
```

Verify proof:

```bash
./rx7900xtx-24g/build/qingming_stark_g64_verifier \
  rx7900xtx-24g/include/qingming_poseidon2_g64_constants.h \
  geoclock_scale27.qsp
```

Expected verifier result:

```text
status: PASS
proof_format: QSPG64
public_input_binding: PASS
statement_digest: PASS
trace_openings: PASS
quotient_fri_check: PASS
local_air_checks: PASS
quotient_relation_checks: PASS
```

## Verified full scale matrix

The retained-tree benchmark matrix has been verified from SCALE20 through SCALE27.

```text
SCALE | rows    | NTT                 | retained MiB | proof total ms | verify
------|---------|---------------------|--------------|----------------|-------
20    | 65536   | rowwise fallback    | 11.999       | 104.809        | PASS
21    | 131072  | rowwise fallback    | 23.999       | 124.814        | PASS
22    | 262144  | rowwise fallback    | 47.999       | 158.471        | PASS
23    | 524288  | rowwise fallback    | 95.999       | 222.443        | PASS
24    | 1048576 | rowwise fallback    | 191.999      | 342.280        | PASS
25    | 2097152 | rowwise fallback    | 383.999      | 567.461        | PASS
26    | 4194304 | rowwise fallback    | 767.999      | 1041.924       | PASS
27    | 8388608 | fast_prelayout_xyz  | 1535.999     | 2041.975       | PASS
```

SCALE27 is the primary FAST XYZ benchmark.

Full details are in:

```text
docs/BENCHMARK_RX7900XTX_24G.md
docs/BENCHMARK_SCALE_MATRIX_RX7900XTX_24G.csv
```

## Benchmark chart placeholder

The full SCALE20-SCALE27 data is now available, but this package does not include a generated chart image yet.

Recommended chart for README:

```text
title: QSPG64 retained-tree proving time by scale
x-axis: scale_log2
y-axis: proof_total_ms
```

Recommended second chart:

```text
title: Retained Merkle tree memory by scale
x-axis: scale_log2
y-axis: retained_merkle_tree_mib
```

Generate and add the chart in a later documentation pass.

## Final baseline statement

`qingming-stark-g64` provides a reproducible CLI-based QSPG64 STARK proving and verification backend verified on AMD RX 7900 XTX 24GB.

The official contract is:

```text
source-visible backend
explicit CLI prover
inspectable QSPG64 proof file
standalone verifier
retained Merkle tree proof builder
compiled AIR profile integration path
```
