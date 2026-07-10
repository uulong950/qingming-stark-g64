# Community wrapper guidance

This directory intentionally does not contain an official SDK implementation.

Official integration surface:

```text
CLI prover
QSPG64 .qsp proof file
standalone verifier
```

Recommended wrapper pattern:

```text
call rx7900xtx-24g/build/qingming_stark_g64_backend
write/read .qsp proof files
call rx7900xtx-24g/build/qingming_stark_g64_verifier
parse PASS/FAIL output
```

Do not assume `libqingming_stark_g64.so` exists in this baseline.

C++ users can wrap the CLI with a process runner or integrate source-level code explicitly.
