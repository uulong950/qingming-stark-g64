# Integration Policy

`qingming-stark-g64` is not a black-box proving SDK.

License:

```text
Apache-2.0
```

The official integration surface is:

```text
CLI prover
QSPG64 .qsp proof file
standalone verifier
```

This package intentionally does not provide:

```text
libqingming_stark_g64.so
official C ABI
official C++ SDK
Rust crate
Python package
black-box binary SDK
```

## Reason

The goal of this baseline is reproducibility and inspectability.

The project keeps the integration boundary explicit:

```text
source-visible backend
command-line prover
inspectable proof file
standalone verifier
deterministic PASS/FAIL verification
```

Avoiding a shared-library SDK prevents the proof system from becoming an opaque black box.

## Official interface

### 1. Prover CLI

```text
rx7900xtx-24g/build/qingming_stark_g64_backend
```

### 2. Proof file

```text
*.qsp
QSPG64 full STARK proof
```

The `.qsp` file is the stable exchange object.

### 3. Standalone verifier

```text
rx7900xtx-24g/build/qingming_stark_g64_verifier
```

Expected result:

```text
status: PASS
```

## Community wrapper guidance

Community wrappers should call the CLI and exchange `.qsp` files.

Recommended wrapper methods:

```text
Python subprocess
Rust std::process::Command
Go os/exec
Node child_process
C/C++ process wrapper
Docker wrapper
CI benchmark wrapper
```

A wrapper should:

```text
1. call the prover CLI
2. persist the .qsp file
3. call the standalone verifier
4. parse PASS/FAIL output
5. treat verifier failure as proof failure
```

## Not a stable ABI

The headers in `include/` are protocol metadata and frozen constants only.

They are not an official C ABI.

Current `include/` contents:

```text
qingming_poseidon2_g64_constants.h
qingming_proof_format.h
qingming_air_profile.h
```

No ABI header is provided in this baseline.

## Business integration path

Upper-layer business logic should integrate by compiling a new AIR profile.

A compiled AIR profile owns:

```text
trace generator
constraint evaluator
quotient evaluator
local verifier checks
air_id
public input layout
```

The backend remains responsible for:

```text
Goldilocks field arithmetic
Poseidon2-G64 hashing
NTT
Merkle commitments
FRI
QSPG64 proof format
standalone verification framework
```

## Policy summary

```text
Official:
  CLI prover
  QSPG64 proof file
  standalone verifier

Community:
  CLI wrappers
  Docker wrappers
  CI wrappers
  source-level integration

Not included:
  libqingming_stark_g64.so
  black-box SDK
  official ABI
```
