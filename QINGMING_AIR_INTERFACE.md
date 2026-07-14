# QINGMING AIR Interface

This document defines the minimal contract for a hand-written AIR evaluator in the current project phase.

## Required identity

Every AIR must declare:

```text
air_id
air_revision
```

The pair must uniquely identify the mathematical statement. Any incompatible change to trace layout, public inputs, constraint order, or constraint meaning requires a new revision.

## Required metadata

```text
trace_width
trace_rows or row-count rule
public input schema
public output schema
maximum constraint degree
constraint ordering
```

## Required behavior

An implementation must define:

1. trace initialization;
2. transition from the current row to the next row;
3. boundary constraints;
4. transition constraints;
5. public input/output binding;
6. deterministic trace fingerprint for cross-backend testing.

C++, Rust, and GPU implementations must produce the same canonical field elements and evaluate constraints in the same declared order.

## Field

All values are canonical Goldilocks field elements:

```text
p = 2^64 - 2^32 + 1
0 <= value < p
```

Non-canonical inputs must be rejected before they are used as field elements.

## Current proof boundary

`QMG64P01` remains bound to the frozen 64-column Compute AIR. The examples in `examples/` are cross-backend AIR evaluators only. They do not alter `QMG64P01`, do not reuse its AIR identity, and do not claim to emit custom-AIR STARK proofs.

A future proof format that supports selectable AIR packages must bind at least `air_id`, `air_revision`, and the public-input schema into the statement and transcript.
