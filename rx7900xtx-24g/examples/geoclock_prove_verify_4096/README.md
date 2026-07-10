# GEOCLOCK 4096 prove and verify

Build:

```bash
make -C rx7900xtx-24g
```

Generate proof:

```bash
./rx7900xtx-24g/build/qingming_stark_g64_backend \
  rx7900xtx-24g/include/qingming_poseidon2_g64_constants.h \
  --mode stark-prove \
  --leaves 4096 \
  --cols 16 \
  --final-rows 1 \
  --proof-out geoclock_4096.qsp
```

Verify proof:

```bash
./rx7900xtx-24g/build/qingming_stark_g64_verifier \
  rx7900xtx-24g/include/qingming_poseidon2_g64_constants.h \
  geoclock_4096.qsp
```

Expected:

```text
opening_source: retained_merkle_trees
status: PASS
proof_format: QSPG64
trace_openings: PASS
quotient_fri_check: PASS
local_air_checks: PASS
quotient_relation_checks: PASS
```
