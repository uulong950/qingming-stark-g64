# QINGMING-STARK-G64

QINGMING-STARK-G64 is a canonical STARK implementation over the Goldilocks 64-bit field. The repository contains independent C++ and Rust CPU references, a full RX 7900 XTX GPU prover, canonical proof serialization, and fail-closed verification under one frozen mathematical contract.

The canonical contract is:

```text
QINGMING_STARK_G64_CONTRACT.md
```

Contract revision: `QMG64-FINAL-3`  
Proof format: `QMG64P01`  
Supported Scale range: `2^20` through `2^27`

## Measured RX 7900 XTX Performance

The following results were measured on an AMD RX 7900 XTX 24 GB. Each Scale was measured five times after warm-up, for 40 successful measured runs in total.

Every measured run produced the expected deterministic trace root, proof length, proof FNV-1a-64 value, complete proof bytes, and a successful canonical verification result.

| Scale | GPU prover | CPU verification | End-to-end | Total CV | Proof size |
|---:|---:|---:|---:|---:|---:|
| `2^20` | 92.25 ms | 148.99 ms | 241.24 ms | 0.379% | 526.9 KiB |
| `2^21` | 120.66 ms | 168.43 ms | 289.09 ms | 0.590% | 593.4 KiB |
| `2^22` | 172.58 ms | 188.48 ms | 361.07 ms | 0.475% | 663.9 KiB |
| `2^23` | 266.24 ms | 210.27 ms | 476.51 ms | 0.262% | 738.5 KiB |
| `2^24` | 450.42 ms | 233.06 ms | 683.47 ms | 0.181% | 817.0 KiB |
| `2^25` | 807.83 ms | 257.27 ms | 1,065.10 ms | 0.063% | 899.5 KiB |
| `2^26` | 1,522.62 ms | 283.44 ms | 1,806.06 ms | 0.050% | 986.1 KiB |
| `2^27` | 2,959.71 ms | 310.72 ms | 3,270.43 ms | 0.129% | 1,076.6 KiB |

`GPU prover` covers the direct GPU proving path. `End-to-end` includes proof generation and canonical CPU verification. Benchmark results are specific to the tested machine, software stack, clock behavior, and thermal conditions.

At `2^24`, the complete prove-and-verify path finishes in approximately 683 ms. At the maximum supported Scale, `2^27`, it finishes in approximately 3.27 seconds while committing to 134,217,728 post-LDE base-field elements.

## What Scale Means

Scale is not a transaction count and is not the row count of one trace column.

For `Scale = 2^K`:

```text
total post-LDE elements S = 2^K
committed columns W       = 64
LDE rows M                = S / 64 = 2^(K - 6)
trace rows N              = M / 8  = 2^(K - 9)
FRI folds R               = K - 10
```

The fixed blowup factor is 8.

| Scale | Original trace rows | LDE rows | Total post-LDE elements | FRI folds |
|---:|---:|---:|---:|---:|
| `2^20` | 2,048 | 16,384 | 1,048,576 | 10 |
| `2^21` | 4,096 | 32,768 | 2,097,152 | 11 |
| `2^22` | 8,192 | 65,536 | 4,194,304 | 12 |
| `2^23` | 16,384 | 131,072 | 8,388,608 | 13 |
| `2^24` | 32,768 | 262,144 | 16,777,216 | 14 |
| `2^25` | 65,536 | 524,288 | 33,554,432 | 15 |
| `2^26` | 131,072 | 1,048,576 | 67,108,864 | 16 |
| `2^27` | 262,144 | 2,097,152 | 134,217,728 | 17 |

The amount of application work represented by one trace row depends on the application encoding. A Scale value therefore describes the cryptographic trace commitment size, not a universal number of transactions, instructions, or business events.

## Real-Time Proving and Higher-Level Proofs

The measured sub-second result at `2^24` makes Qingming suitable as a low-latency proving core for statements that can be expressed through its fixed 64-column AIR and batching model.

Possible higher-level integrations include:

- batched application state-transition proofs;
- rollup or settlement batch proofs for a purpose-built state machine;
- deterministic game, simulation, or control-system state proofs;
- verifiable accounting, reconciliation, and risk-calculation batches;
- telemetry, audit-log, and data-pipeline integrity proofs;
- a high-performance proving component beneath a recursive wrapper or aggregation layer.

These are integration directions rather than built-in applications. Each application must define how its witness, public inputs, and state transitions map into the canonical AIR or into a separately designed compatible AIR.

The practical significance of the benchmark is that a large committed execution trace can be proven on a single consumer GPU with deterministic proof bytes and independently checked by both CPU implementations. This enables low-latency local proving, reproducible benchmark baselines, hardware-backend comparison, and application-specific proof systems without requiring a GPU cluster.

## Canonical Mathematical Contract

### Fields

The base field is the Goldilocks prime field:

```text
p = 2^64 - 2^32 + 1
```

The quadratic extension is:

```text
Fp2 = Fp[u] / (u^2 - 7)
```

Base-field elements use canonical unsigned little-endian 64-bit encoding in `[0, p)`. Decoders reject non-canonical values, malformed lengths, unsupported revisions, truncated inputs, and trailing bytes.

### Fixed Parameters

```text
trace width       = 64 columns
LDE blowup        = 8
query count       = 64
FRI terminal size = 16 extension elements
AIR degree        = 2
```

### AIR

Each row contains four groups of sixteen columns:

```text
x[0..15], a[0..15], m[0..15], h[0..15]
```

For each lane `j`, with cyclic indexing modulo 16:

```text
m_j       - x_j * x_(j+1)                         = 0
h_j       - x_j^2                                 = 0
a'_j      - a_j - m_j                             = 0
x'_j      - c_j - x_j - 3*x_(j+1) - 5*h_j - 7*m_j = 0
```

The first row binds the initial state and zero accumulators. The final row binds the public final accumulator.

### LDE and Composition

Each trace column is interpolated over the original trace domain and evaluated over an eight-times-larger coset domain. The final GPU path performs trace generation, interpolation, coset expansion, forward NTT, composition, FRI, Merkle commitments, and opening extraction without a host-side LDE bridge.

The normalized AIR transition and boundary constraints are mixed with transcript challenge powers into one extension-field composition quotient.

### Poseidon2 and Merkle Commitments

The frozen Poseidon2 configuration is:

```text
width          = 12
rate           = 8
capacity       = 4
digest         = 4 base-field elements
S-box          = x^7
full rounds    = 8
partial rounds = 22
```

Trace leaves commit to the indexed complete 64-element LDE row. FRI leaves commit to the indexed extension-field value. Internal nodes use domain-separated Poseidon2 hashing.

### Transcript and FRI

The Fiat-Shamir transcript binds the public input, trace root, committed quotient and FRI roots, terminal vector, and query challenges in a frozen order.

Binary FRI folds the initial composition word until 16 extension-field values remain. The verifier checks all authenticated openings, every fold relation, and the terminal degree bound.

### Proof Format

A `QMG64P01` proof contains:

- the format magic, revision, and trace-row exponent;
- a canonical copy of the public input;
- the indexed trace root and committed FRI roots;
- the 16-element terminal vector;
- 64 transcript-derived queries;
- current and next trace openings with Merkle paths;
- both authenticated FRI pair values for every committed layer.

For fixed Scale, witness, constants, and contract revision, the proof bytes are deterministic.

Scale `2^20`, seed 7, frozen regression vector:

```text
trace_root=
0x497e153d6e9d6e2a;
0x44105c9bf84e6af1;
0x72fb0e27747412d1;
0x59d0f6e5ccb64a56

proof_bytes=539516
proof_fnv=1a0614193dbbff79
```

## Security Status

The verifier is fail-closed. It binds the external public input, consumes the complete proof byte string, replays the transcript, verifies every Merkle path, checks the AIR and quotient identities, checks every FRI fold, and enforces the terminal degree bound.

The C++, Rust, and RX 7900 XTX implementations are checked against the same frozen mathematical contract and canonical proof vectors. Qualification compares trace roots, proof sizes, proof hashes, complete proof bytes, repeated-run determinism, and independent verifier results.

Malformed encodings, wrong public statements, proof mutations, truncated data, and trailing bytes are rejected by the reference verification tests.

The project has not undergone an independent third-party cryptographic audit.

## Engineering Status

QINGMING-STARK-G64 is a complete single-machine, fixed-AIR canonical STARK engine within its declared contract.

The qualified implementation includes:

- independent C++ and Rust CPU references;
- a direct RX 7900 XTX HIP proving path;
- deterministic canonical proof serialization;
- independent C++ and Rust verification;
- Scale `2^20` through `2^27`;
- direct device-resident trace/LDE, FRI vectors, Merkle trees, and query openings;
- witness input and streamed canonical trace input;
- per-stage end-to-end timing reports;
- byte-for-byte cross-implementation qualification.

The mathematical contract is normative. Source code, scripts, generated proofs, and reports conform only when they agree with that contract.

## Requirements

For all three implementations:

```text
Linux(Ubuntu 24.04 LTS)
```

For the C++ reference:

```text
g++ with C++20 support
```

For the Rust reference:

```text
rustc
```

For the RX 7900 XTX backend:

```text
ROCm
hipcc
AMD RX 7900 XTX 24 GB
default target: gfx1100
```

## C++ CPU Reference

Build:

```bash
mkdir -p build

g++ -O3 -std=c++20 \
  cpu-cpp/qingming_stark_g64.cpp \
  -o build/qingming_stark_g64_cpp
```

Run the regression tests:

```bash
build/qingming_stark_g64_cpp test
build/qingming_stark_g64_cpp scale-contract
```

Generate a canonical proof:

```bash
build/qingming_stark_g64_cpp \
  proof-file 20 \
  build/cpp-scale-20.qmg64p01
```

Verify a canonical proof:

```bash
build/qingming_stark_g64_cpp \
  verify-file 20 \
  build/cpp-scale-20.qmg64p01
```

Run the Scale matrix:

```bash
build/qingming_stark_g64_cpp scale-matrix 20 27
```

Generate a canonical trace file:

```bash
build/qingming_stark_g64_cpp \
  trace-file 20 \
  build/trace-scale-20.qmt64t01
```

## Rust CPU Reference

Build:

```bash
mkdir -p build

rustc -O \
  cpu-rust/qingming_stark_g64.rs \
  -o build/qingming_stark_g64_rust
```

Run the regression tests:

```bash
build/qingming_stark_g64_rust test
build/qingming_stark_g64_rust scale-contract
```

Generate a canonical proof:

```bash
build/qingming_stark_g64_rust \
  proof-file 20 \
  build/rust-scale-20.qmg64p01
```

Verify a canonical proof:

```bash
build/qingming_stark_g64_rust \
  verify-file 20 \
  build/rust-scale-20.qmg64p01
```

Run the Scale matrix:

```bash
build/qingming_stark_g64_rust scale-matrix 20 27
```

## RX 7900 XTX 24 GB GPU Prover

Build:

```bash
mkdir -p build

hipcc -O3 -std=c++20 --offload-arch=gfx1100 \
  rx7900xtx-24g/qingming_stark_g64_backend.hip \
  -Idevices/rx7900xtx-24g \
  -o build/qingming_stark_g64_backend
```

Generate a proof and timing report:

```bash
build/qingming_stark_g64_backend \
  --scale 20 \
  --repeat 3 \
  --seed 7 \
  --constants rx7900xtx-24g/qingming_poseidon2_g64_constants.h \
  --proof-out build/gpu-scale-20.qmg64p01 \
  --report-out build/gpu-scale-20-timing.csv
```

The GPU prover accepts either a canonical witness or a canonical trace input:

```bash
build/qingming_stark_g64_backend \
  --scale 20 \
  --repeat 1 \
  --witness witness.qmw64i01 \
  --constants rx7900xtx-24g/qingming_poseidon2_g64_constants.h \
  --proof-out build/gpu-witness-scale-20.qmg64p01 \
  --report-out build/gpu-witness-scale-20-timing.csv
```

```bash
build/qingming_stark_g64_backend \
  --scale 20 \
  --repeat 1 \
  --trace-in build/trace-scale-20.qmt64t01 \
  --constants rx7900xtx-24g/qingming_poseidon2_g64_constants.h \
  --proof-out build/gpu-trace-scale-20.qmg64p01 \
  --report-out build/gpu-trace-scale-20-timing.csv
```

`--witness` and `--trace-in` are mutually exclusive.

## Input Formats

Canonical witness input:

```text
8 bytes: ASCII QMW64I01
16 x u64 little-endian canonical Goldilocks elements
end of file
```

Canonical trace input:

```text
8 bytes: ASCII QMT64T01
u32 revision = 1
u32 scale_log2
u64 trace_rows
u32 columns = 64
u32 reserved = 0
trace_rows x 64 x u64 little-endian canonical field elements
end of file
```

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.
