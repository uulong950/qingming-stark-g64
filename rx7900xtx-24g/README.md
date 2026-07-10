# RX 7900 XTX 24GB backend

This is the current verified backend for `qingming-stark-g64`.

## Official integration surface

```text
CLI prover
QSPG64 proof file
standalone verifier
```

This package does not ship `libqingming_stark_g64.so`.

## Build

```bash
make -C rx7900xtx-24g
```

Outputs:

```text
rx7900xtx-24g/build/qingming_stark_g64_backend
rx7900xtx-24g/build/qingming_stark_g64_verifier
```

## Constants

```text
rx7900xtx-24g/include/qingming_poseidon2_g64_constants.h
```

Expected fingerprints:

```text
params_fingerprint       = 0xad77784b434bb34c
test_vectors_fingerprint = 0xffdf9225a1834ebc
```

## Full proof generation

```bash
./rx7900xtx-24g/build/qingming_stark_g64_backend \
  rx7900xtx-24g/include/qingming_poseidon2_g64_constants.h \
  --mode stark-prove \
  --leaves 4096 \
  --cols 16 \
  --final-rows 1 \
  --proof-out geoclock_4096.qsp
```

Expected proof-builder line:

```text
opening_source: retained_merkle_trees
```

## Standalone verification

```bash
./rx7900xtx-24g/build/qingming_stark_g64_verifier \
  rx7900xtx-24g/include/qingming_poseidon2_g64_constants.h \
  geoclock_4096.qsp
```

## Include directory

`include/` only contains protocol metadata and frozen constants. It does not define an official C ABI.
