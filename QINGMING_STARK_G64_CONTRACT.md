# QINGMING-STARK-G64 Canonical Mathematical Contract

Status: **frozen normative contract**  
Revision: **QMG64-FINAL-3**  
Canonical proof format: **QMG64P01**  
Supported protocol Scale: **2^20 through 2^27 inclusive**

This is the only normative mathematical contract in this delivery. Source code,
scripts, reports, and generated proofs are conforming only when they agree with
this file. No implementation-specific behavior may override it.

## 1. Fields and canonical encoding

The base field is the Goldilocks prime field

\[
\mathbb F_p,\qquad p=2^{64}-2^{32}+1.
\]

The quadratic extension is

\[
\mathbb F_{p^2}=\mathbb F_p[u]/(u^2-7).
\]

A base-field element is encoded as an unsigned little-endian 64-bit integer in
`[0,p)`. An extension element `a + b u` is encoded as `(a,b)`. Decoders reject
non-canonical coordinates, malformed lengths, unknown revisions, and trailing
bytes.

## 2. Scale and all dimensional mappings

Fixed parameters:

\[
W=64,\quad B=8,\quad Q=64,\quad T_{FRI}=16.
\]

`Scale = 2^K` means the **total number of base-field elements across all 64
post-LDE trace columns**, not the row count of one column.

\[
20\le K\le27,
\]

\[
S=2^K,
\quad M=S/W=2^{K-6},
\quad N=M/B=2^{K-9}.
\]

Here `M` is the post-LDE row count and trace Merkle leaf count; `N` is the
original trace row count. The number of binary FRI folds is

\[
R=\log_2 M-\log_2 16=K-10.
\]

| Scale | total LDE elements S | columns | LDE rows / Merkle leaves M | trace rows N | trace elements | LDE bytes | FRI folds | committed FRI roots | vectors incl. terminal |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 2^20 | 1,048,576 | 64 | 16,384 (2^14) | 2,048 (2^11) | 131,072 | 8 MiB | 10 | 10 | 11 |
| 2^21 | 2,097,152 | 64 | 32,768 (2^15) | 4,096 (2^12) | 262,144 | 16 MiB | 11 | 11 | 12 |
| 2^22 | 4,194,304 | 64 | 65,536 (2^16) | 8,192 (2^13) | 524,288 | 32 MiB | 12 | 12 | 13 |
| 2^23 | 8,388,608 | 64 | 131,072 (2^17) | 16,384 (2^14) | 1,048,576 | 64 MiB | 13 | 13 | 14 |
| 2^24 | 16,777,216 | 64 | 262,144 (2^18) | 32,768 (2^15) | 2,097,152 | 128 MiB | 14 | 14 | 15 |
| 2^25 | 33,554,432 | 64 | 524,288 (2^19) | 65,536 (2^16) | 4,194,304 | 256 MiB | 15 | 15 | 16 |
| 2^26 | 67,108,864 | 64 | 1,048,576 (2^20) | 131,072 (2^17) | 8,388,608 | 512 MiB | 16 | 16 | 17 |
| 2^27 | 134,217,728 | 64 | 2,097,152 (2^21) | 262,144 (2^18) | 16,777,216 | 1 GiB | 17 | 17 | 18 |

The committed FRI vector sizes are

```text
2^(K-6), 2^(K-7), ..., 2^5
```

and the uncommitted terminal vector has `2^4 = 16` extension elements.

## 3. AIR

Each row contains four groups of sixteen columns:

\[
(x_0,\ldots,x_{15}),
(a_0,\ldots,a_{15}),
(m_0,\ldots,m_{15}),
(h_0,\ldots,h_{15}).
\]

For lane `j`, indices are cyclic modulo 16 and

\[
c_j=\operatorname{canonical}(0x9e3779b97f4a7c15+j).
\]

The transition constraints are

\[
m_j-x_jx_{j+1}=0,
\]

\[
h_j-x_j^2=0,
\]

\[
a'_j-a_j-m_j=0,
\]

\[
x'_j-c_j-x_j-3x_{j+1}-5h_j-7m_j=0.
\]

The first row binds `x_j` to the public initial state and `a_j=0`. The final
trace row accumulators bind to the public final accumulator. AIR degree is two.

## 4. Trace generation and LDE

Let `H_N=<omega_N>` be the trace domain. The post-LDE domain is the coset

\[
7H_M,\qquad M=8N.
\]

Each of the 64 trace columns is interpolated from `H_N`, multiplied in
coefficient form by powers of the coset shift `7`, zero-padded to `M`, and
forward transformed over `H_M`.

The final GPU path accepts a 16-element witness or canonical trace input and
performs trace generation/interpolation/LDE directly on the GPU. `QMC64LD1` is
not part of the final proving path and must not be produced, consumed, or
required by final qualification.

Canonical trace input uses `QMT64T01`: revision 1, Scale exponent, trace row
count, 64 columns, and exactly `N×64` canonical little-endian field elements.
The implementation streams this payload to device memory and does not retain a
full host-side trace copy.

## 5. Composition quotient

For `z` in `7H_M`, transition constraints are divided by

\[
Z_{trans}(z)=\frac{z^N-1}{z-\omega_N^{-1}}.
\]

Initial and final boundary constraints use denominators `z-1` and
`z-omega_N^{-1}`. The 112 normalized constraint values are mixed in the
specified lane/order using successive powers of transcript challenge
`alpha in F_(p^2)`. The resulting quotient has degree below `N` and is the
initial `M`-element FRI word.

## 6. Poseidon2 and Merkle commitments

Frozen Poseidon2 parameters:

- width 12, rate 8, capacity 4;
- digest four base-field elements;
- S-box `x^7`;
- 8 full rounds and 22 partial rounds;
- frozen constants in `qingming_poseidon2_g64_constants.h`.

Canonical Merkle leaves are domain-separated hashes that include the
zero-based leaf index as the first absorbed field element:

```text
trace leaf i = H_LEAF(i || complete 64-element LDE row i)
FRI leaf i   = H_LEAF(i || a_i || b_i)
```

Nodes are

```text
H_NODE(left_digest[4] || right_digest[4])
```

with a complete binary tree and leaf-to-root sibling paths.

## 7. Transcript

The transcript is initialized with the frozen parameter and vector
fingerprints. It absorbs in this exact order:

1. public-input digest;
2. canonical indexed trace root;
3. each committed quotient/FRI root before deriving that layer's beta;
4. hash of the 16-element terminal vector;
5. query challenges.

Extension challenges use two consecutive base-field squeezes. Exactly 64 query
indices are generated by rejection sampling into `[0,M)`.

## 8. Binary FRI

For layer offset `g_l`, pair `a=f(x)`, `b=f(-x)`, and challenge `beta_l`,

\[
f_{l+1}(x^2)=\frac{a+b}{2}+\beta_l\frac{a-b}{2x}.
\]

The offset is squared after each fold. Folding stops at 16 values. The verifier
interpolates the terminal vector over its final coset and rejects non-zero
coefficients above the folded degree bound.

## 9. QMG64P01 proof and verifier

A proof contains:

- magic `QMG64P01`, revision 1, and trace-row exponent;
- canonical public input copy;
- indexed trace root, quotient root, and intermediate FRI roots;
- 16 terminal extension values;
- 64 transcript-derived queries;
- current and next trace rows with paths;
- both FRI pair values and both paths for every committed layer.

The verifier is fail-closed. It must consume all bytes, bind the external public
input, replay the transcript, verify all Merkle paths, AIR/quotient identities,
FRI folds, and terminal degree bound.

## 10. Determinism

For fixed Scale, witness, constants, and revision, proof bytes are a pure
function of the statement. Every repeated run must produce exactly the same:

- trace root;
- proof length;
- proof FNV-1a-64;
- complete QMG64P01 byte string.

Scale 20 frozen regression vector for seed 7:

```text
trace_root=
0x497e153d6e9d6e2a;
0x44105c9bf84e6af1;
0x72fb0e27747412d1;
0x59d0f6e5ccb64a56
proof_bytes=539516
proof_fnv=1a0614193dbbff79
```

## 11. Unified final qualification

`verify_final.sh` evaluates the complete qualified path in one run.

### 11.1 Scale 20–27 canonical sweep

For every Scale, compare canonical C++, Rust, and GPU trace root, proof length,
proof FNV, complete proof bytes, and verifier result.

### 11.2 Stability

Run every requested GPU Scale at least the requested repeat count.
Byte-for-byte proof identity across repetitions is mandatory.

### 11.3 End-to-end timing

Reports distinguish at least:

```text
witness/input I/O
CPU LDE (zero in the direct-GPU path)
H2D
GPU trace generation
GPU inverse NTT/interpolation
GPU coset expansion
GPU forward NTT/LDE
GPU trace Merkle
GPU composition
GPU FRI Merkle
GPU FRI folds
GPU opening extraction
compact D2H
serialization
verification
proof file I/O
total
```

### 11.4 Direct GPU LDE

The qualified path starts from witness or canonical trace input and constructs
the canonical LDE on the GPU. `QMC64LD1` is forbidden in the final executable
and final scripts.

### 11.5 Device-resident openings

Full trace/LDE matrices, FRI vectors, and Merkle trees remain on device through
query opening extraction. The host receives only roots/challenges, terminal
values, compact opening records, final serialization, and file output.

## 12. Independent references and source integrity

C++ and Rust remain independent complete CPU implementations. The final GPU
translation unit embeds the canonical C++ proof structures/verifier for host
assembly and rejection checking while all large proving data and opening
extraction remain device-resident.

Final RX7900XTX delivery:

```text
devices/rx7900xtx-24g/src/qingming_stark_g64_backend.hip
devices/rx7900xtx-24g/include/qingming_poseidon2_g64_constants.h
```

Frozen SHA-256 values:

```text
b6a2bcab2c9e68c575219024eef4b55c83cac5873736a7fb71f8413b2d1eea8f
  devices/rx7900xtx-24g/src/qingming_stark_g64_backend.hip
8d5bc00fa981101b6600ce2ab10f0e258a05f20305712f47599716324910b90d
  devices/rx7900xtx-24g/include/qingming_poseidon2_g64_constants.h
```

Any mismatch is a qualification failure.
