# GEOCLOCK SCALE24 prove and verify

Build:

```bash
make -C rx7900xtx-24g
```

Generate proof:

```bash
./rx7900xtx-24g/build/qingming_stark_g64_backend \
  rx7900xtx-24g/include/qingming_poseidon2_g64_constants.h \
  --mode stark-prove \
  --scale 24 \
  --cols 16 \
  --final-rows 1 \
  --proof-out geoclock_scale24.qsp
```

Verify proof:

```bash
./rx7900xtx-24g/build/qingming_stark_g64_verifier \
  rx7900xtx-24g/include/qingming_poseidon2_g64_constants.h \
  geoclock_scale24.qsp
```

Expected retained-tree reference:

```text
retained_merkle_tree_mib: about 191.999
verify: PASS
```
