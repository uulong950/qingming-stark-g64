# RX 7900 XTX 24GB Benchmark

This document records the RX 7900 XTX 24GB benchmark contract for `qingming-stark-g64`.

License:

```text
Apache-2.0
```

Verified profile:

```text
QINGMING-AIR-GEOCLOCK-G64
```

Backend:

```text
rx7900xtx-24g
```

Device target:

```text
AMD RX 7900 XTX 24GB
```

Proof mode:

```text
QSPG64 full STARK proof
retained Merkle trees
standalone verifier
```

## Benchmark goal

Measure proving time, retained Merkle tree memory, and standalone verifier correctness across scale levels.

The full verified benchmark matrix is:

```text
SCALE20
SCALE21
SCALE22
SCALE23
SCALE24
SCALE25
SCALE26
SCALE27
```

SCALE16 / 4096 rows is retained as the small correctness baseline.

## Fields recorded

```text
scale_log2
layer0_rows
ntt_operator
retained_merkle_tree_mib
trace_h2d_ms
trace_ntt_total_ms
trace_merkle_commit_ms
quotient_eval_ms
quotient_snapshot_ms
quotient_fri_total_ms
transcript_ms
opening_extraction_ms
write_proof_ms
proof_total_ms
verifier_status
trace_root
quotient_root
final_root
```

Machine-readable table:

```text
docs/BENCHMARK_SCALE_MATRIX_RX7900XTX_24G.csv
```

## Full scale result table

```text
SCALE | rows    | NTT                 | retained MiB | H2D ms | NTT ms | trace Merkle ms | quotient FRI ms | opening ms | write ms | proof total ms | verify
------|---------|---------------------|--------------|--------|--------|-----------------|------------------|------------|----------|----------------|-------
20    | 65536   | rowwise fallback    | 11.999       | 3.036  | 1.815  | 16.263          | 70.439           | 2.041      | 1.858    | 104.809        | PASS
21    | 131072  | rowwise fallback    | 23.999       | 3.281  | 1.812  | 19.569          | 84.188           | 2.111      | 1.970    | 124.814        | PASS
22    | 262144  | rowwise fallback    | 47.999       | 3.721  | 3.085  | 27.079          | 104.328          | 2.238      | 2.124    | 158.471        | PASS
23    | 524288  | rowwise fallback    | 95.999       | 5.287  | 4.728  | 43.111          | 140.404          | 2.459      | 2.312    | 222.443        | PASS
24    | 1048576 | rowwise fallback    | 191.999      | 7.801  | 10.827 | 72.725          | 204.220          | 2.504      | 2.600    | 342.280        | PASS
25    | 2097152 | rowwise fallback    | 383.999      | 12.573 | 20.182 | 134.602         | 322.508          | 3.149      | 2.705    | 567.461        | PASS
26    | 4194304 | rowwise fallback    | 767.999      | 21.421 | 43.623 | 260.181         | 576.178          | 6.921      | 2.885    | 1041.924       | PASS
27    | 8388608 | fast_prelayout_xyz  | 1535.999     | 40.630 | 21.871 | 524.707         | 1193.391         | 14.707     | 3.068    | 2041.975       | PASS
```

SCALE27 is the primary FAST XYZ benchmark.

SCALE20-SCALE26 are retained-tree and proof/verifier stability tests using `rowwise_radix2_fallback`.

## SCALE16 correctness baseline

```text
scale_log2: 16
layer0_rows: 4096
trace_columns: 16
quotient_columns: 16
fri_rounds: 12
fri_query_count: 32
ntt_operator: rowwise_radix2_fallback

retained_merkle_tree_mib: 0.750
opening_extraction_ms: 1.812
proof_total_ms: 71.626

verifier: PASS
```

Roots:

```text
trace_root:
[0x1651a45634c64c82,
 0x639f45c2540fd3ba,
 0xc56c93482508c310,
 0xb770ced45b0e5dd9]

quotient_root:
[0x8369f6ed82916806,
 0x77d9f8a8eea5e698,
 0xc3fc8c044abdd072,
 0x12358d96840e81d9]

final_root:
[0xc78a4c9a0d7e5424,
 0xc4d3f6ebd5acc7ff,
 0x9a4640b245067788,
 0xa37702b126860f05]
```

## SCALE20

```text
scale_log2: 20
layer0_rows: 65536
trace_columns: 16
quotient_columns: 16
fri_rounds: 16
fri_root_count: 17
fri_query_count: 32
ntt_operator: rowwise_radix2_fallback

transition_ratio:  0x1544ef2335d17997
composition_alpha: 0x7d801c6b2e43f183

trace_h2d_ms:            3.036
trace_ntt_total_ms:      1.815
trace_merkle_commit_ms: 16.263
quotient_eval_ms:        0.022
quotient_snapshot_ms:    0.017
quotient_fri_total_ms:  70.439
transcript_ms:           1.906

retained_merkle_tree_mib: 11.999
opening_extraction_ms:    2.041
write_proof_ms:           1.858
proof_total_ms:         104.809

verifier: PASS
```

Roots:

```text
trace_root:
[0xb40514838cb3ddbb,
 0x0e65e7b62b798482,
 0xe51a0826adcf21e1,
 0x2869b33d6f7f4a00]

quotient_root:
[0x6218df5ad7ef85a5,
 0xe34026180575cbc7,
 0x7ad7c3946de060a3,
 0x7195cbac5b9cc6eb]

final_root:
[0xc78a4c9a0d7e5424,
 0xc4d3f6ebd5acc7ff,
 0x9a4640b245067788,
 0xa37702b126860f05]
```

## SCALE21

```text
scale_log2: 21
layer0_rows: 131072
fri_rounds: 17
fri_root_count: 18
ntt_operator: rowwise_radix2_fallback

transition_ratio:  0xe0ee099310bba1e2
composition_alpha: 0x4b6fd852459c9bd4

trace_h2d_ms:            3.281
trace_ntt_total_ms:      1.812
trace_merkle_commit_ms: 19.569
quotient_eval_ms:        0.034
quotient_snapshot_ms:    0.024
quotient_fri_total_ms:  84.188
transcript_ms:           1.980

retained_merkle_tree_mib: 23.999
opening_extraction_ms:    2.111
write_proof_ms:           1.970
proof_total_ms:         124.814

verifier: PASS
```

Roots:

```text
trace_root:
[0x49142ffd41af1d06,
 0xd8453a56d6503601,
 0xe4fefdae2fbcd7fd,
 0x42990158c8bf013a]

quotient_root:
[0xd3013ec3e7e1faa3,
 0x287ab5d3607c76ec,
 0x29436fa613045735,
 0x2739c94db879b1d1]

final_root:
[0xc78a4c9a0d7e5424,
 0xc4d3f6ebd5acc7ff,
 0x9a4640b245067788,
 0xa37702b126860f05]
```

## SCALE22

```text
scale_log2: 22
layer0_rows: 262144
fri_rounds: 18
fri_root_count: 19
ntt_operator: rowwise_radix2_fallback

transition_ratio:  0xf6b2cffe2306baac
composition_alpha: 0x63e0dca804dd16ba

trace_h2d_ms:            3.721
trace_ntt_total_ms:      3.085
trace_merkle_commit_ms: 27.079
quotient_eval_ms:        0.058
quotient_snapshot_ms:    0.039
quotient_fri_total_ms: 104.328
transcript_ms:           1.975

retained_merkle_tree_mib: 47.999
opening_extraction_ms:    2.238
write_proof_ms:           2.124
proof_total_ms:         158.471

verifier: PASS
```

Roots:

```text
trace_root:
[0x47a5049be793f1ed,
 0x7b6a1bcb679b458b,
 0x9b2087ac8edc9975,
 0x4c4bfc10802bd6c6]

quotient_root:
[0x5bcad34fa453fac1,
 0xce78ba4532f3e6d7,
 0x0b7d6fb2dc46fee3,
 0x45a789dbdc17cff3]

final_root:
[0xc78a4c9a0d7e5424,
 0xc4d3f6ebd5acc7ff,
 0x9a4640b245067788,
 0xa37702b126860f05]
```

## SCALE23

```text
scale_log2: 23
layer0_rows: 524288
fri_rounds: 19
fri_root_count: 20
ntt_operator: rowwise_radix2_fallback

transition_ratio:  0x54df9630bf79450e
composition_alpha: 0x09d6b539910919f2

trace_h2d_ms:            5.287
trace_ntt_total_ms:      4.728
trace_merkle_commit_ms: 43.111
quotient_eval_ms:        0.149
quotient_snapshot_ms:    0.158
quotient_fri_total_ms: 140.404
transcript_ms:           2.152

retained_merkle_tree_mib: 95.999
opening_extraction_ms:    2.459
write_proof_ms:           2.312
proof_total_ms:         222.443

verifier: PASS
```

Roots:

```text
trace_root:
[0x9e1ddd2fc8e63083,
 0x04dbd1f7adeada3f,
 0x293342cd2d7571c4,
 0x10a1d02e3bc32e41]

quotient_root:
[0x2775c7fb4f64e883,
 0x1ea239b0714c4b90,
 0xd66f97fb7c7483d7,
 0x4f352db17cbb710b]

final_root:
[0xc78a4c9a0d7e5424,
 0xc4d3f6ebd5acc7ff,
 0x9a4640b245067788,
 0xa37702b126860f05]
```

## SCALE24

```text
scale_log2: 24
layer0_rows: 1048576
fri_rounds: 20
fri_root_count: 21
ntt_operator: rowwise_radix2_fallback

transition_ratio:  0xabd0a6e8aa3d8a0e
composition_alpha: 0x50f3492980926d22

trace_h2d_ms:            7.801
trace_ntt_total_ms:     10.827
trace_merkle_commit_ms: 72.725
quotient_eval_ms:        0.284
quotient_snapshot_ms:    0.320
quotient_fri_total_ms: 204.220
transcript_ms:           2.133

retained_merkle_tree_mib: 191.999
opening_extraction_ms:     2.504
write_proof_ms:            2.600
proof_total_ms:          342.280

verifier: PASS
```

Roots:

```text
trace_root:
[0xdd0e2ac217125095,
 0x7c0e0922dd6ad3be,
 0x2b2c8663a0110683,
 0x680a4747ed36b735]

quotient_root:
[0x59f904239a692037,
 0x6da843dcb303252c,
 0xa6d00803c307a7a8,
 0x387b9e62da73c0ba]

final_root:
[0xc78a4c9a0d7e5424,
 0xc4d3f6ebd5acc7ff,
 0x9a4640b245067788,
 0xa37702b126860f05]
```

## SCALE25

```text
scale_log2: 25
layer0_rows: 2097152
fri_rounds: 21
fri_root_count: 22
ntt_operator: rowwise_radix2_fallback

transition_ratio:  0x81281a7b05f9beac
composition_alpha: 0x929e8e542ee920ea

trace_h2d_ms:            12.573
trace_ntt_total_ms:      20.182
trace_merkle_commit_ms: 134.602
quotient_eval_ms:         0.583
quotient_snapshot_ms:     0.678
quotient_fri_total_ms:  322.508
transcript_ms:            2.294

retained_merkle_tree_mib: 383.999
opening_extraction_ms:     3.149
write_proof_ms:            2.705
proof_total_ms:          567.461

verifier: PASS
```

Roots:

```text
trace_root:
[0xae76ea79181b6052,
 0x4accbff715ae9623,
 0x3d72c7d1470f38da,
 0xf27308ea0f8112af]

quotient_root:
[0x7dbe06ce85834713,
 0x910808969287b14d,
 0x2ca9ebab575598e9,
 0x7cc49a73dc6645ad]

final_root:
[0xc78a4c9a0d7e5424,
 0xc4d3f6ebd5acc7ff,
 0x9a4640b245067788,
 0xa37702b126860f05]
```

## SCALE26

```text
scale_log2: 26
layer0_rows: 4194304
fri_rounds: 22
fri_root_count: 23
ntt_operator: rowwise_radix2_fallback

transition_ratio:  0xfbd41c6b8caa3302
composition_alpha: 0xdbc077cde79f39a6

trace_h2d_ms:            21.421
trace_ntt_total_ms:      43.623
trace_merkle_commit_ms: 260.181
quotient_eval_ms:         1.444
quotient_snapshot_ms:     1.366
quotient_fri_total_ms:  576.178
transcript_ms:            2.296

retained_merkle_tree_mib: 767.999
opening_extraction_ms:     6.921
write_proof_ms:            2.885
proof_total_ms:         1041.924

verifier: PASS
```

Roots:

```text
trace_root:
[0xa65c3dc76c59adcb,
 0xa279de786aa3a52b,
 0xbeb66e538dd8f266,
 0xb0cb9f1207cf8e77]

quotient_root:
[0xa9118acb9f0c50f2,
 0x139bb7d84971e820,
 0xf14d822cd5e569e3,
 0xfc4e34902f73632e]

final_root:
[0xc78a4c9a0d7e5424,
 0xc4d3f6ebd5acc7ff,
 0x9a4640b245067788,
 0xa37702b126860f05]
```

## SCALE27 primary FAST XYZ benchmark

```text
scale_log2: 27
layer0_rows: 8388608
fri_rounds: 23
fri_root_count: 24
ntt_operator: fast_prelayout_xyz

transition_ratio:  0x30ba2ecd5e93e76d
composition_alpha: 0x858951334c758a1f

trace_h2d_ms:             40.630
trace_ntt_total_ms:       21.871
trace_merkle_commit_ms:  524.707
quotient_eval_ms:          2.416
quotient_snapshot_ms:      2.756
quotient_fri_total_ms:  1193.391
transcript_ms:             2.439

retained_merkle_tree_bytes: 1610611872
retained_merkle_tree_mib:  1535.999
opening_extraction_ms:      14.707
write_proof_ms:              3.068
proof_total_ms:           2041.975

verifier: PASS
```

Roots:

```text
trace_root:
[0xfbaf6c6775d3e6f8,
 0xc0af5ccbbc020ef0,
 0xc29468860a80b107,
 0x0cde73c13bee75cb]

quotient_root:
[0x40fcc95c2c0fd4db,
 0x5da1a714fd81446b,
 0x606603b4795430b0,
 0xc4ef3581c0826be1]

final_root:
[0xc2e2f6b8fd1132b9,
 0xbbabc5cc0961015d,
 0xafa38535d326def9,
 0x8a8a3737065b877f]
```

## Full scale benchmark commands

Build once:

```bash
make -C rx7900xtx-24g
```

Replace `XX` with the target scale from `20` through `27`.

```bash
./rx7900xtx-24g/build/qingming_stark_g64_backend \
  rx7900xtx-24g/include/qingming_poseidon2_g64_constants.h \
  --mode stark-prove \
  --scale XX \
  --cols 16 \
  --final-rows 1 \
  --proof-out geoclock_scaleXX.qsp
```

```bash
./rx7900xtx-24g/build/qingming_stark_g64_verifier \
  rx7900xtx-24g/include/qingming_poseidon2_g64_constants.h \
  geoclock_scaleXX.qsp
```

## Future README chart

The full SCALE20-SCALE27 data has been collected.

This package still does not include a generated chart image.

Recommended chart for a later documentation pass:

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

Primary benchmark:

```text
SCALE27 / cols=16 / RX 7900 XTX 24GB / fast_prelayout_xyz
```
