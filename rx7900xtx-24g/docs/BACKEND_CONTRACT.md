# RX 7900 XTX Backend Contract

Official integration surface:

```text
CLI prover
QSPG64 proof file
standalone verifier
```

Source files:

```text
src/qingming_stark_g64_backend.hip
src/qingming_stark_g64_verifier.cpp
```

Supported modes:

```text
--mode stark-check
--mode stark-perf
--mode stark-prove --proof-out proof.qsp
```

The standalone verifier accepts QSPG64 `.qsp` full STARK proof files.

The proof builder uses retained Merkle trees during `stark-prove`.
