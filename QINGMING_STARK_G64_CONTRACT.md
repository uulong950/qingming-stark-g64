# QINGMING-STARK-G64 Canonical Mathematical Contract

> **Status:** Frozen normative contract
> **Canonical proof format:** `QMG64P01`
> **Supported protocol Scale:** `2^20` through `2^27`, inclusive

This document is the **only normative mathematical contract** in this delivery.

Source code, scripts, reports, generated proofs, and implementation behavior are conforming only when they agree with this document. No implementation-specific behavior may override this contract.

---

## 1. Fields and Canonical Encoding

The base field is the Goldilocks prime field:

$$
\mathbb{F}_p,
\qquad
p = 2^{64} - 2^{32} + 1.
$$

The quadratic extension field is:

$$
\mathbb{F}_{p^2}
================

\mathbb{F}_p[u]/(u^2 - 7).
$$

### 1.1 Base-field encoding

A base-field element is encoded as an unsigned little-endian 64-bit integer in the canonical range:

$$
0 \le x < p.
$$

### 1.2 Extension-field encoding

An extension-field element

$$
a + bu
$$

is encoded as the ordered pair:

```text
(a, b)
```

where both coordinates are canonical base-field elements.

### 1.3 Decoder requirements

Decoders MUST reject:

* non-canonical field coordinates;
* malformed lengths;
* unknown revisions;
* truncated encodings;
* trailing bytes.

---

## 2. Scale and Dimensional Mappings

The protocol uses the following fixed parameters:

| Symbol             | Value | Meaning                    |
| ------------------ | ----: | -------------------------- |
| $W$                |    64 | Number of trace columns    |
| $B$                |     8 | LDE blowup factor          |
| $Q$                |    64 | Number of queries          |
| $T_{\mathrm{FRI}}$ |    16 | Terminal FRI vector length |

`Scale = 2^K` denotes the **total number of base-field elements across all 64 post-LDE trace columns**.

It does **not** denote the row count of a single column.

The supported range is:

$$
20 \le K \le 27.
$$

Define:

$$
S = 2^K,
$$

$$
M = \frac{S}{W} = 2^{K-6},
$$

$$
N = \frac{M}{B} = 2^{K-9}.
$$

Where:

* $S$ is the total number of post-LDE base-field elements;
* $M$ is the post-LDE row count;
* $M$ is also the trace Merkle leaf count;
* $N$ is the original trace row count.

The number of binary FRI folds is:

$$
R
=

# \log_2 M - \log_2 16

K - 10.
$$

### 2.1 Canonical Scale table

|    Scale | Total LDE elements $S$ | Columns | LDE rows / Merkle leaves $M$ |     Trace rows $N$ | Trace elements | LDE bytes | FRI folds | Committed FRI roots | Vectors including terminal |
| -------: | ---------------------: | ------: | ---------------------------: | -----------------: | -------------: | --------: | --------: | ------------------: | -------------------------: |
| $2^{20}$ |              1,048,576 |      64 |            16,384 ($2^{14}$) |   2,048 ($2^{11}$) |        131,072 |     8 MiB |        10 |                  10 |                         11 |
| $2^{21}$ |              2,097,152 |      64 |            32,768 ($2^{15}$) |   4,096 ($2^{12}$) |        262,144 |    16 MiB |        11 |                  11 |                         12 |
| $2^{22}$ |              4,194,304 |      64 |            65,536 ($2^{16}$) |   8,192 ($2^{13}$) |        524,288 |    32 MiB |        12 |                  12 |                         13 |
| $2^{23}$ |              8,388,608 |      64 |           131,072 ($2^{17}$) |  16,384 ($2^{14}$) |      1,048,576 |    64 MiB |        13 |                  13 |                         14 |
| $2^{24}$ |             16,777,216 |      64 |           262,144 ($2^{18}$) |  32,768 ($2^{15}$) |      2,097,152 |   128 MiB |        14 |                  14 |                         15 |
| $2^{25}$ |             33,554,432 |      64 |           524,288 ($2^{19}$) |  65,536 ($2^{16}$) |      4,194,304 |   256 MiB |        15 |                  15 |                         16 |
| $2^{26}$ |             67,108,864 |      64 |         1,048,576 ($2^{20}$) | 131,072 ($2^{17}$) |      8,388,608 |   512 MiB |        16 |                  16 |                         17 |
| $2^{27}$ |            134,217,728 |      64 |         2,097,152 ($2^{21}$) | 262,144 ($2^{18}$) |     16,777,216 |     1 GiB |        17 |                  17 |                         18 |

### 2.2 FRI vector sizes

The committed FRI vector sizes are:

```text
2^(K-6), 2^(K-7), ..., 2^5
```

The final uncommitted terminal vector contains:

```text
2^4 = 16
```

extension-field elements.

---

## 3. AIR Definition

Each trace row contains four groups of sixteen columns:

$$
(x_0,\ldots,x_{15}),
$$

$$
(a_0,\ldots,a_{15}),
$$

$$
(m_0,\ldots,m_{15}),
$$

$$
(h_0,\ldots,h_{15}).
$$

For each lane $j$, indices are cyclic modulo 16.

Define:

$$
c_j
===

\operatorname{canonical}
\left(
\mathtt{0x9e3779b97f4a7c15} + j
\right).
$$

### 3.1 Transition constraints

For every lane $j$:

$$
m_j - x_jx_{j+1} = 0,
$$

$$
h_j - x_j^2 = 0,
$$

$$
a'_j - a_j - m_j = 0,
$$

$$
x'*j - c_j - x_j - 3x*{j+1} - 5h_j - 7m_j = 0.
$$

### 3.2 Boundary constraints

The first row binds:

* $x_j$ to the public initial state;
* $a_j = 0$.

The final trace row binds the accumulators to the public final accumulator.

### 3.3 AIR degree

The AIR has algebraic degree:

$$
2.
$$

---

## 4. Trace Generation and LDE

Let the trace domain be:

$$
H_N = \langle \omega_N \rangle.
$$

The post-LDE evaluation domain is the multiplicative coset:

$$
7H_M,
\qquad
M = 8N.
$$

For each of the 64 trace columns:

1. interpolate the column from $H_N$;
2. convert it to coefficient form;
3. multiply the coefficients by successive powers of the coset shift $7$;
4. zero-pad the coefficient vector to length $M$;
5. perform a forward transform over $H_M$.

### 4.1 Final GPU proving path

The final GPU path accepts either:

* a 16-element witness; or
* canonical trace input.

It performs the following operations directly on the GPU:

* trace generation;
* interpolation;
* coset expansion;
* LDE.

`QMC64LD1` is **not** part of the final proving path.

The final qualified implementation MUST NOT:

* produce `QMC64LD1`;
* consume `QMC64LD1`;
* require `QMC64LD1`.

### 4.2 Canonical trace input

Canonical trace input uses the format:

```text
QMT64T01
```

It contains:

* revision `1`;
* Scale exponent;
* trace row count;
* column count fixed to `64`;
* exactly `N × 64` canonical little-endian base-field elements.

The implementation streams this payload into device memory and does not retain a complete host-side trace copy.

---

## 5. Composition Quotient

For:

$$
z \in 7H_M,
$$

transition constraints are divided by:

$$
Z_{\mathrm{trans}}(z)
=====================

\frac{z^N - 1}{z - \omega_N^{-1}}.
$$

Initial boundary constraints use the denominator:

$$
z - 1.
$$

Final boundary constraints use the denominator:

$$
z - \omega_N^{-1}.
$$

The protocol produces 112 normalized constraint values.

These values are mixed in the specified lane and constraint order using successive powers of the transcript challenge:

$$
\alpha \in \mathbb{F}_{p^2}.
$$

The resulting composition quotient:

* has degree strictly below $N$;
* forms the initial $M$-element FRI word.

---

## 6. Poseidon2 and Merkle Commitments

### 6.1 Frozen Poseidon2 parameters

The protocol uses the following frozen Poseidon2 parameters:

| Parameter      |                 Value |
| -------------- | --------------------: |
| Width          |                    12 |
| Rate           |                     8 |
| Capacity       |                     4 |
| Digest size    | 4 base-field elements |
| S-box          |                 $x^7$ |
| Full rounds    |                     8 |
| Partial rounds |                    22 |

The frozen round constants are defined in:

```text
qingming_poseidon2_g64_constants.h
```

### 6.2 Canonical trace leaves

Trace leaves are domain-separated hashes that include the zero-based leaf index as the first absorbed field element:

```text
trace leaf i = H_LEAF(i || complete 64-element LDE row i)
```

### 6.3 Canonical FRI leaves

FRI leaves are encoded as:

```text
FRI leaf i = H_LEAF(i || a_i || b_i)
```

where `a_i` and `b_i` are extension-field coordinates according to the canonical encoding.

### 6.4 Internal Merkle nodes

Internal nodes are computed as:

```text
H_NODE(left_digest[4] || right_digest[4])
```

The Merkle tree is a complete binary tree.

Authentication paths are ordered from leaf to root.

---

## 7. Transcript

The transcript is initialized with the frozen:

* parameter fingerprint;
* vector fingerprint.

It then absorbs data in the following exact order:

1. public-input digest;
2. canonical indexed trace root;
3. each committed quotient or FRI root, before deriving that layer's $\beta$ challenge;
4. hash of the 16-element terminal vector;
5. query challenges.

### 7.1 Extension challenges

An extension-field challenge is constructed from two consecutive base-field squeezes.

### 7.2 Query generation

Exactly 64 query indices are generated by rejection sampling into:

$$
[0,M).
$$

No biased modular reduction is permitted.

---

## 8. Binary FRI

For FRI layer $\ell$, let:

* $g_\ell$ be the layer offset;
* $a = f(x)$;
* $b = f(-x)$;
* $\beta_\ell$ be the layer challenge.

The binary fold is:

$$
f_{\ell+1}(x^2)
===============

\frac{a+b}{2}
+
\beta_\ell
\frac{a-b}{2x}.
$$

After each fold, the layer offset is squared:

$$
g_{\ell+1} = g_\ell^2.
$$

Folding stops when 16 extension-field values remain.

The terminal vector is not committed as another Merkle layer.

The verifier:

1. interpolates the 16-element terminal vector over its final coset;
2. computes its coefficient representation;
3. rejects the proof if any coefficient above the folded degree bound is non-zero.

---

## 9. `QMG64P01` Proof Format and Verifier

A canonical proof contains:

* magic bytes `QMG64P01`;
* revision `1`;
* trace-row exponent;
* canonical public-input copy;
* indexed trace root;
* composition quotient root;
* intermediate FRI roots;
* 16 terminal extension-field values;
* 64 transcript-derived query indices;
* current trace rows and authentication paths;
* next trace rows and authentication paths;
* both FRI pair values for every committed FRI layer;
* both Merkle authentication paths for every committed FRI layer.

### 9.1 Verifier requirements

The verifier is fail-closed.

It MUST:

* consume the entire proof byte string;
* reject trailing bytes;
* bind the externally supplied public input;
* validate the canonical embedded public-input copy;
* replay the complete transcript;
* regenerate all challenges and query indices;
* verify every trace Merkle path;
* verify every FRI Merkle path;
* verify all AIR identities;
* verify the composition quotient identities;
* verify every FRI fold;
* verify the terminal degree bound.

---

## 10. Determinism

For fixed:

* Scale;
* witness;
* constants;
* protocol revision;

the proof bytes are a pure function of the statement.

Every repeated proving run MUST produce exactly the same:

* trace root;
* proof length;
* proof FNV-1a-64 value;
* complete `QMG64P01` byte string.

### 10.1 Frozen Scale 20 regression vector

For Scale `2^20` and seed `7`:

```text
trace_root=
0x497e153d6e9d6e2a;
0x44105c9bf84e6af1;
0x72fb0e27747412d1;
0x59d0f6e5ccb64a56

proof_bytes=539516
proof_fnv=1a0614193dbbff79
```

---

## 11. Unified Final Qualification

The canonical qualification entry point is:

```text
benchmarks/run.sh
```

The script evaluates the complete qualified proving path.

### 11.1 Correctness qualification

The canonical correctness invocation is:

```bash
./benchmarks/run.sh correctness 20 27 3
```

The arguments specify:

```text
correctness <minimum Scale exponent> <maximum Scale exponent> <GPU repeat count>
```

For the full supported Scale range, qualification covers `2^20` through `2^27`, inclusive.

Qualification compares the applicable canonical C++, Rust, and GPU outputs, including:

* trace root;
* proof length;
* proof FNV-1a-64;
* complete proof bytes;
* verifier result.

The qualification process also covers:

* C++ correctness regression;
* Rust correctness regression;
* C++ Scale contract regression;
* Rust Scale contract regression;
* Fibonacci C++ / Rust / HIP consistency;
* Poseidon2-chain C++ / Rust / HIP consistency;
* GPU proof determinism;
* C++ verifier acceptance;
* Rust verifier acceptance;
* malformed-proof rejection.

A successful full correctness qualification terminates with:

```text
air_examples=PASS
correctness=PASS
```

### 11.2 Canonical Scale sweep

For every requested Scale, the GPU implementation MUST produce:

* a canonical trace root;
* a canonical proof length;
* a canonical proof FNV-1a-64 value;
* a valid complete `QMG64P01` proof;
* a passing verifier result.

Within the configured CPU proving range, qualification MUST compare:

* C++ proof output;
* Rust proof output;
* GPU proof output;
* complete proof bytes.

For GPU-only proving Scales, the resulting proof MUST be accepted independently by both:

* the canonical C++ verifier;
* the canonical Rust verifier.

### 11.3 Stability

Every requested GPU Scale MUST run at least the requested repeat count.

All repeated proofs MUST be byte-for-byte identical.

Repeated runs MUST produce exactly the same:

* trace root;
* proof length;
* proof FNV-1a-64 value;
* complete proof bytes;
* verifier result.

### 11.4 Performance qualification

The canonical performance invocation is:

```bash
WARMUP=1 ./benchmarks/run.sh performance 20 27 5
```

The arguments specify:

```text
performance <minimum Scale exponent> <maximum Scale exponent> <measured repeat count>
```

Performance qualification MUST distinguish at least the following stages:

```text
witness/input I/O
CPU LDE
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

In the direct-GPU path:

```text
CPU LDE = 0
```

### 11.5 Direct GPU LDE

The qualified path starts from either:

* a witness; or
* canonical trace input.

The canonical LDE is constructed directly on the GPU.

`QMC64LD1` is forbidden in:

* the final executable;
* `benchmarks/run.sh`;
* the final qualification workflow;
* the final proving workflow.

### 11.6 Device-resident openings

The following data remain resident on the device through query-opening extraction:

* complete trace matrices;
* complete LDE matrices;
* FRI vectors;
* Merkle trees.

The host receives only:

* commitment roots;
* transcript challenges;
* terminal values;
* compact opening records;
* final serialized proof data;
* proof file output.

---

## 12. Independent References and Source Integrity

The C++ and Rust implementations remain independent complete CPU implementations.

The final GPU translation unit embeds the canonical C++:

* proof structures;
* host-side proof assembly;
* verifier;
* rejection checks.

All large proving data and query-opening extraction remain device-resident.

### 12.1 Final RX 7900 XTX delivery files

```text
rx7900xtx-24g/qingming_stark_g64_backend.hip
rx7900xtx-24g/qingming_poseidon2_g64_constants.h
```

### 12.2 Frozen SHA-256 values

```text
b6a2bcab2c9e68c575219024eef4b55c83cac5873736a7fb71f8413b2d1eea8f
  rx7900xtx-24g/qingming_stark_g64_backend.hip

8d5bc00fa981101b6600ce2ab10f0e258a05f20305712f47599716324910b90d
  rx7900xtx-24g/qingming_poseidon2_g64_constants.h
```

Any source-integrity mismatch is a qualification failure.

---

## 13. Normative Interpretation

The keywords **MUST**, **MUST NOT**, **REQUIRED**, and **SHALL** indicate mandatory protocol requirements.

Where this contract conflicts with:

* source code;
* comments;
* scripts;
* reports;
* generated proofs;
* implementation-specific documentation;

this contract takes precedence.

A conforming implementation MUST agree with this document at the level of:

* field arithmetic;
* canonical encoding;
* dimensional mappings;
* AIR semantics;
* trace generation;
* LDE;
* composition quotient;
* Poseidon2 commitments;
* Merkle encoding;
* transcript order;
* FRI folding;
* proof serialization;
* verifier behavior;
* deterministic proof bytes;
* final qualification behavior.
