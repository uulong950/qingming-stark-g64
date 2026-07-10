# QSPG64 Proof Format

`.qsp` is the full QINGMING-STARK-G64 proof file.

It contains:

```text
header
public input material
public_input_digest
statement_digest
trace_root
quotient FRI roots
final values
quotient FRI pair openings
trace current/next openings
```

The standalone verifier checks:

```text
public input binding
statement digest
composition alpha
trace current openings
trace next openings
quotient FRI Merkle openings
FRI fold consistency
local AIR relation
quotient relation
final root
```

`QMPG64` is only the internal quotient-FRI proof core. A complete STARK proof is `QSPG64`.
