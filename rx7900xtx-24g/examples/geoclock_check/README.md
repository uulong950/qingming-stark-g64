# GEOCLOCK correctness check

Build:

```bash
make -C rx7900xtx-24g
```

Run:

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
