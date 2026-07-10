# QINGMING-STARK-G64 Contract

## Fixed backend

```text
Goldilocks / G64
Poseidon2-G64
FAST XYZ NTT
Poseidon2 Merkle commitment
FRI commit-fold chain
QMPG64 quotient-FRI proof core
QSPG64 full STARK proof
```

## STARK layer

```text
compiled AIR
trace commitment
randomized quotient
quotient FRI
trace openings
local AIR verifier checks
standalone full verifier
```

## AIR profile replacement boundary

An AIR profile owns:

```text
trace generator
constraint evaluator
quotient evaluator
local verifier checks
air_id
public input layout
```

The backend owns:

```text
NTT
Merkle commitment
transcript
composition challenge
FRI proof
proof format
verifier framework
```

## Opening extraction

The current backend uses retained Merkle trees during `stark-prove`:

```text
opening_source = retained_merkle_trees
```

This uses more GPU memory to avoid rebuilding trace and quotient Merkle trees during proof opening extraction.
