# GEOCLOCK SCALE27 prove and verify

This is the primary RX 7900 XTX 24GB FAST XYZ benchmark.

Build:

```bash
make -C rx7900xtx-24g
```

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

Expected:

```text
ntt_operator: fast_prelayout_xyz
opening_source: retained_merkle_trees
retained_merkle_tree_mib: about 1535.999
status: PASS
```
