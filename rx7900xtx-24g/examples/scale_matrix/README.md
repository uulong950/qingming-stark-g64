# SCALE matrix

The full SCALE20-SCALE27 benchmark results, commands, and roots are maintained in:

```text
../../../docs/BENCHMARK_RX7900XTX_24G.md
```

Machine-readable CSV:

```text
../../../docs/BENCHMARK_SCALE_MATRIX_RX7900XTX_24G.csv
```

Build once:

```bash
make -C rx7900xtx-24g
```

Command template:

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

SCALE20-SCALE27 have been verified PASS on RX 7900 XTX 24GB.

A README chart can be generated later from the CSV data. This package does not include a generated chart image.
