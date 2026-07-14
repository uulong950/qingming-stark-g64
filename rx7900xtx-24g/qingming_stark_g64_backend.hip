// QINGMING-STARK-G64 canonical RX7900XTX backend.
// SPDX-License-Identifier: Apache-2.0
//
// Build:
//   hipcc -O3 -std=c++20 rx7900xtx-24g/qingming_stark_g64_rx7900xtx.hip \
//     -o build/qingming_canonical_gpu_final
//
// This translation unit embeds the frozen CPU reference for canonical proof
// structures/verification and the mature RX7900XTX backend for field,
// Poseidon2, and baseline GPU primitives. The new canonical path keeps trace,
// LDE, composition, FRI vectors, Merkle trees, and opening extraction on the
// device. The host receives only roots/challenges, terminal values, compact
// openings, and final proof bytes.

#define main qingming_embedded_cpu_reference_main
#include "../cpu-cpp/qingming_stark_g64.cpp"
#undef main

#define main qingming_embedded_mature_backend_main
// Embedded RX7900XTX/GFX1100 field, Poseidon2, NTT, Merkle, and FRI primitives.
// This implementation is part of the single final backend translation unit.

#include <hip/hip_runtime.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using u64 = uint64_t;
using u128 = __uint128_t;

static constexpr u64 G64_P = 0xffffffff00000001ULL;
static constexpr u64 G64_C = 0x00000000ffffffffULL; // 2^64 == 2^32 - 1 mod p

static constexpr int P2_T = 12;
static constexpr int P2_RATE = 8;
static constexpr int P2_CAPACITY = 4;
static constexpr int P2_DIGEST = 4;
static constexpr int P2_RF = 8;
static constexpr int P2_RP = 22;

static constexpr int P2_RC_EXT_LEN = P2_RF * P2_T;
static constexpr int P2_RC_INT_LEN = P2_RP;
static constexpr int P2_MATRIX_LEN = P2_T * P2_T;
static constexpr int P2_DIAG_LEN = P2_T;
static constexpr int P2_DOMAIN_LEN = 6;

enum DomainIndex : int {
    DOMAIN_PERMUTATION_TEST = 0,
    DOMAIN_HASH_ELEMENTS    = 1,
    DOMAIN_MERKLE_LEAF      = 2,
    DOMAIN_MERKLE_NODE      = 3,
    DOMAIN_FRI_COMMITMENT   = 4,
    DOMAIN_TRANSCRIPT       = 5
};

#define HIP_CHECK(call) do {                                      \
    hipError_t _err = (call);                                     \
    if (_err != hipSuccess) {                                     \
        std::ostringstream _oss;                                  \
        _oss << "HIP error: " << hipGetErrorString(_err)          \
             << " at " << __FILE__ << ":" << __LINE__;           \
        throw std::runtime_error(_oss.str());                     \
    }                                                             \
} while (0)

// Frozen Poseidon2 constants storage binding.
// Same flat layout as qingming_poseidon2_g64_constants.h.
// This is not a layout conversion.
__constant__ u64 d_p2_rc_ext[P2_RC_EXT_LEN];
__constant__ u64 d_p2_rc_int[P2_RC_INT_LEN];
__constant__ u64 d_p2_matrix[P2_MATRIX_LEN];
__constant__ u64 d_p2_diag[P2_DIAG_LEN];
__constant__ u64 d_p2_domains[P2_DOMAIN_LEN];

struct FrozenPoseidon2 {
    std::vector<u64> rc_ext;
    std::vector<u64> rc_int;
    std::vector<u64> matrix;
    std::vector<u64> diag;
    std::vector<u64> domains;
    u64 params_fingerprint = 0;
    u64 vectors_fingerprint = 0;
};

enum class Mode {
    Check,
    Perf,
    Sweep,
    FriCheck,
    FriPerf,
    FriSweep,
    E2ECheck,
    E2EPerf,
    E2ESweep,
    Proof,
    StarkCheck,
    StarkPerf,
    StarkProve
};

struct Options {
    std::string constants_path;
    Mode mode = Mode::Check;

    int leaf_count = 4096;
    int committed_columns = 16;
    int query_index = 123;

    int scale_k = -1;
    int scale_min = 20;
    int scale_max = 27;

    int repeat = 1;
    int final_rows = 1;
    int fri_query_count = 32;
    std::string proof_out = "qingming_proof_g64.qmp";
};

// -----------------------------
// Utility
// -----------------------------

static bool is_power_of_two_u64(u64 x) {
    return x && ((x & (x - 1)) == 0);
}

static int log2_u64(u64 x) {
    int r = 0;
    while (x > 1) {
        x >>= 1;
        ++r;
    }
    return r;
}

static std::string hex64(u64 x) {
    std::ostringstream os;
    os << "0x" << std::hex << std::setw(16) << std::setfill('0') << x;
    return os.str();
}

static std::string read_all(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open file: " + path);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

static bool is_hex_digit(char c) {
    return ('0' <= c && c <= '9') ||
           ('a' <= c && c <= 'f') ||
           ('A' <= c && c <= 'F');
}

static u64 parse_hex_token(const std::string& raw) {
    std::string s = raw;
    while (!s.empty()) {
        char c = s.back();
        if (c == 'U' || c == 'u' || c == 'L' || c == 'l') s.pop_back();
        else break;
    }

    if (s.size() < 3 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X')) {
        throw std::runtime_error("bad hex token: " + raw);
    }

    u64 x = 0;
    for (size_t i = 2; i < s.size(); ++i) {
        char c = s[i];
        if (!is_hex_digit(c)) throw std::runtime_error("bad hex token: " + raw);

        u64 v = 0;
        if ('0' <= c && c <= '9') v = (u64)(c - '0');
        else if ('a' <= c && c <= 'f') v = (u64)(10 + c - 'a');
        else v = (u64)(10 + c - 'A');

        x = (x << 4) | v;
    }

    return x;
}

static std::vector<u64> extract_array(const std::string& text, const std::string& name) {
    size_t p = text.find(name);
    if (p == std::string::npos) throw std::runtime_error("array not found: " + name);

    size_t l = text.find('{', p);
    size_t r = text.find("};", l);
    if (l == std::string::npos || r == std::string::npos) {
        throw std::runtime_error("bad array body: " + name);
    }

    std::string body = text.substr(l + 1, r - l - 1);
    std::vector<u64> out;

    for (size_t i = 0; i < body.size();) {
        if (i + 2 < body.size() && body[i] == '0' && (body[i + 1] == 'x' || body[i + 1] == 'X')) {
            size_t j = i + 2;
            while (j < body.size() && is_hex_digit(body[j])) ++j;
            while (j < body.size() && (body[j] == 'U' || body[j] == 'u' || body[j] == 'L' || body[j] == 'l')) ++j;
            out.push_back(parse_hex_token(body.substr(i, j - i)));
            i = j;
        } else {
            ++i;
        }
    }

    return out;
}

static u64 extract_scalar(const std::string& text, const std::string& name) {
    size_t p = text.find(name);
    if (p == std::string::npos) throw std::runtime_error("scalar not found: " + name);

    size_t eq = text.find('=', p);
    if (eq == std::string::npos) throw std::runtime_error("bad scalar: " + name);

    size_t i = text.find("0x", eq);
    if (i == std::string::npos) i = text.find("0X", eq);
    if (i == std::string::npos) throw std::runtime_error("scalar value not found: " + name);

    size_t j = i + 2;
    while (j < text.size() && is_hex_digit(text[j])) ++j;
    while (j < text.size() && (text[j] == 'U' || text[j] == 'u' || text[j] == 'L' || text[j] == 'l')) ++j;

    return parse_hex_token(text.substr(i, j - i));
}

static void require_len(const std::vector<u64>& v, size_t expected, const char* name) {
    if (v.size() != expected) {
        std::ostringstream os;
        os << name << " length mismatch: got " << v.size() << ", expected " << expected;
        throw std::runtime_error(os.str());
    }

    for (u64 x : v) {
        if (x >= G64_P) {
            throw std::runtime_error(std::string(name) + " contains non-canonical field element");
        }
    }
}

static FrozenPoseidon2 load_poseidon2_constants(const std::string& path) {
    const std::string text = read_all(path);

    FrozenPoseidon2 f;
    f.rc_ext = extract_array(text, "QM_P2_G64_RC_EXTERNAL");
    f.rc_int = extract_array(text, "QM_P2_G64_RC_INTERNAL");
    f.matrix = extract_array(text, "QM_P2_G64_EXTERNAL_MATRIX");
    f.diag = extract_array(text, "QM_P2_G64_INTERNAL_DIAG");
    f.domains = extract_array(text, "QM_P2_G64_DOMAIN_SEPARATORS");
    f.params_fingerprint = extract_scalar(text, "QM_P2_G64_PARAMS_FINGERPRINT");
    f.vectors_fingerprint = extract_scalar(text, "QM_P2_G64_TEST_VECTORS_FINGERPRINT");

    require_len(f.rc_ext, P2_RC_EXT_LEN, "RC_EXTERNAL");
    require_len(f.rc_int, P2_RC_INT_LEN, "RC_INTERNAL");
    require_len(f.matrix, P2_MATRIX_LEN, "EXTERNAL_MATRIX");
    require_len(f.diag, P2_DIAG_LEN, "INTERNAL_DIAG");
    require_len(f.domains, P2_DOMAIN_LEN, "DOMAIN_SEPARATORS");

    for (u64 x : f.diag) {
        if (x == 0) throw std::runtime_error("INTERNAL_DIAG contains zero");
    }

    return f;
}

static u64 fnv1a64(const std::string& s) {
    u64 h = 1469598103934665603ULL;
    for (unsigned char c : s) {
        h ^= (u64)c;
        h *= 1099511628211ULL;
    }
    return h;
}

static u64 mix64(u64 h, u64 x) {
    h ^= x + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return h;
}

static u64 fingerprint_poseidon2_params(const FrozenPoseidon2& f) {
    u64 h = fnv1a64("QINGMING-POSEIDON2-G64-PARAMS");
    for (u64 x : f.rc_ext) h = mix64(h, x);
    for (u64 x : f.rc_int) h = mix64(h, x);
    for (u64 x : f.matrix) h = mix64(h, x);
    for (u64 x : f.diag) h = mix64(h, x);
    for (u64 x : f.domains) h = mix64(h, x);
    return h;
}

static u64 fingerprint_values(const std::vector<u64>& xs, const std::string& label) {
    u64 h = fnv1a64(label);
    for (u64 x : xs) h = mix64(h, x);
    return h;
}

static void check_canonical_matrix(const std::vector<u64>& matrix) {
    for (size_t i = 0; i < matrix.size(); ++i) {
        if (matrix[i] >= G64_P) {
            std::ostringstream os;
            os << "non-canonical committed value at index " << i;
            throw std::runtime_error(os.str());
        }
    }
}

// -----------------------------
// Goldilocks arithmetic
// -----------------------------

__host__ __device__ __forceinline__ u64 g64_add(u64 a, u64 b) {
    u64 res = a + b;
    if (res < a) res += G64_C;
    if (res >= G64_P) res -= G64_P;
    return res;
}

__host__ __device__ __forceinline__ u64 g64_sub(u64 a, u64 b) {
    u64 res = a - b;
    if (a < b) res -= G64_C;
    return res;
}

__host__ __device__ __forceinline__ u64 g64_mul(u64 a, u64 b) {
#ifndef __HIP_DEVICE_COMPILE__
    return (u64)(((u128)a * b) % G64_P);
#else
    // Goldilocks reduction for p = 2^64 - 2^32 + 1.
    u64 L = a * b;
    u64 H = __umul64hi(a, b);

    uint32_t H_hi = (uint32_t)(H >> 32);
    uint32_t H_lo = (uint32_t)(H & 0xffffffffULL);

    u64 t = ((u64)H_lo) << 32;
    u64 res = L;

    bool carry = (res > 0xffffffffffffffffULL - t);
    res += t;

    u64 sub = (u64)H_lo + (u64)H_hi;
    bool borrow = (res < sub);
    res -= sub;

    if (carry && !borrow) {
        bool c2 = (res > 0xffffffffffffffffULL - G64_C);
        res += G64_C;
        if (c2) res += G64_C;
    } else if (borrow && !carry) {
        bool b2 = (res < G64_C);
        res -= G64_C;
        if (b2) res -= G64_C;
    }

    if (res >= G64_P) res -= G64_P;
    return res;
#endif
}

__host__ __device__ __forceinline__ u64 g64_pow7(u64 x) {
    u64 x2 = g64_mul(x, x);
    u64 x3 = g64_mul(x2, x);
    u64 x4 = g64_mul(x2, x2);
    return g64_mul(x3, x4); // x^7
}

// -----------------------------
// CPU Poseidon2 + Merkle reference
// -----------------------------

static void cpu_poseidon2_perm(u64 state[P2_T], const FrozenPoseidon2& f) {
    for (int i = 0; i < P2_T; ++i) {
        if (state[i] >= G64_P) throw std::runtime_error("non-canonical CPU state");
    }


    // Poseidon2 standard construction: initial external linear layer.
    {
        u64 initial_out[P2_T] = {};
        for (int row = 0; row < P2_T; ++row) {
            u64 acc = 0;
            for (int col = 0; col < P2_T; ++col) {
                acc = g64_add(
                    acc,
                    g64_mul(f.matrix[row * P2_T + col], state[col])
                );
            }
            initial_out[row] = acc;
        }
        for (int i = 0; i < P2_T; ++i) state[i] = initial_out[i];
    }

    constexpr int HALF = P2_RF / 2;

    for (int r = 0; r < HALF; ++r) {
        for (int i = 0; i < P2_T; ++i) {
            state[i] = g64_add(state[i], f.rc_ext[r * P2_T + i]);
        }

        for (int i = 0; i < P2_T; ++i) {
            state[i] = g64_pow7(state[i]);
        }

        u64 out[P2_T] = {};
        for (int row = 0; row < P2_T; ++row) {
            u64 acc = 0;
            for (int col = 0; col < P2_T; ++col) {
                acc = g64_add(acc, g64_mul(f.matrix[row * P2_T + col], state[col]));
            }
            out[row] = acc;
        }

        for (int i = 0; i < P2_T; ++i) state[i] = out[i];
    }

    for (int r = 0; r < P2_RP; ++r) {
        state[0] = g64_add(state[0], f.rc_int[r]);
        state[0] = g64_pow7(state[0]);

        u64 total = 0;
        for (int i = 0; i < P2_T; ++i) total = g64_add(total, state[i]);

        u64 out[P2_T] = {};
        for (int i = 0; i < P2_T; ++i) {
            out[i] = g64_add(g64_mul(f.diag[i], state[i]), total);
        }

        for (int i = 0; i < P2_T; ++i) state[i] = out[i];
    }

    for (int r = HALF; r < P2_RF; ++r) {
        for (int i = 0; i < P2_T; ++i) {
            state[i] = g64_add(state[i], f.rc_ext[r * P2_T + i]);
        }

        for (int i = 0; i < P2_T; ++i) {
            state[i] = g64_pow7(state[i]);
        }

        u64 out[P2_T] = {};
        for (int row = 0; row < P2_T; ++row) {
            u64 acc = 0;
            for (int col = 0; col < P2_T; ++col) {
                acc = g64_add(acc, g64_mul(f.matrix[row * P2_T + col], state[col]));
            }
            out[row] = acc;
        }

        for (int i = 0; i < P2_T; ++i) state[i] = out[i];
    }
}

static void cpu_hash_elements(
    const std::vector<u64>& values,
    int domain,
    const FrozenPoseidon2& f,
    u64 digest[P2_DIGEST]
) {
    for (u64 x : values) {
        if (x >= G64_P) throw std::runtime_error("non-canonical hash input");
    }

    u64 state[P2_T] = {};
    state[P2_RATE] = f.domains[domain];

    if (values.empty()) {
        state[0] = g64_add(state[0], 1);
        cpu_poseidon2_perm(state, f);
    } else {
        size_t off = 0;
        while (off < values.size()) {
            size_t chunk = std::min((size_t)P2_RATE, values.size() - off);

            for (size_t i = 0; i < chunk; ++i) {
                state[i] = g64_add(state[i], values[off + i]);
            }

            if (chunk < (size_t)P2_RATE) {
                state[chunk] = g64_add(state[chunk], 1);
            }

            cpu_poseidon2_perm(state, f);
            off += chunk;
        }
    }

    for (int i = 0; i < P2_DIGEST; ++i) digest[i] = state[i];
}

static void cpu_merkle_leaf(
    const std::vector<u64>& matrix,
    int row,
    int cols,
    const FrozenPoseidon2& f,
    u64 digest[P2_DIGEST]
) {
    std::vector<u64> row_values;
    row_values.reserve(cols);

    for (int c = 0; c < cols; ++c) {
        row_values.push_back(matrix[(size_t)row * cols + c]);
    }

    cpu_hash_elements(row_values, DOMAIN_MERKLE_LEAF, f, digest);
}

static void cpu_merkle_node(
    const u64 left[P2_DIGEST],
    const u64 right[P2_DIGEST],
    const FrozenPoseidon2& f,
    u64 parent[P2_DIGEST]
) {
    std::vector<u64> values;
    values.reserve(P2_DIGEST * 2);

    for (int i = 0; i < P2_DIGEST; ++i) values.push_back(left[i]);
    for (int i = 0; i < P2_DIGEST; ++i) values.push_back(right[i]);

    cpu_hash_elements(values, DOMAIN_MERKLE_NODE, f, parent);
}

static std::vector<u64> cpu_build_merkle_tree(
    const std::vector<u64>& matrix,
    int leaves,
    int cols,
    const FrozenPoseidon2& f
) {
    check_canonical_matrix(matrix);

    const int total_nodes = 2 * leaves - 1;
    std::vector<u64> tree((size_t)total_nodes * P2_DIGEST);

    for (int i = 0; i < leaves; ++i) {
        cpu_merkle_leaf(matrix, i, cols, f, &tree[(size_t)i * P2_DIGEST]);
    }

    int cur_nodes = leaves;
    int cur_off = 0;
    int next_off = leaves;

    while (cur_nodes > 1) {
        const int next_nodes = cur_nodes / 2;

        for (int i = 0; i < next_nodes; ++i) {
            const u64* left = &tree[(size_t)(cur_off + 2 * i) * P2_DIGEST];
            const u64* right = &tree[(size_t)(cur_off + 2 * i + 1) * P2_DIGEST];
            u64* parent = &tree[(size_t)(next_off + i) * P2_DIGEST];
            cpu_merkle_node(left, right, f, parent);
        }

        cur_off = next_off;
        next_off += next_nodes;
        cur_nodes = next_nodes;
    }

    return tree;
}

static std::vector<int> merkle_layer_offsets(int leaves) {
    std::vector<int> offsets;

    int off = 0;
    int n = leaves;

    while (n >= 1) {
        offsets.push_back(off);
        off += n;
        n >>= 1;
    }

    return offsets;
}

static bool cpu_verify_opening_from_tree(
    const std::vector<u64>& matrix,
    const std::vector<u64>& tree,
    int leaves,
    int cols,
    int query_index,
    const FrozenPoseidon2& f
) {
    const std::vector<int> offsets = merkle_layer_offsets(leaves);
    const int height = log2_u64((u64)leaves);

    u64 cur[P2_DIGEST];
    cpu_merkle_leaf(matrix, query_index, cols, f, cur);

    int idx = query_index;

    for (int level = 0; level < height; ++level) {
        int sibling = idx ^ 1;
        const u64* sib = &tree[(size_t)(offsets[level] + sibling) * P2_DIGEST];

        u64 next[P2_DIGEST];

        if ((idx & 1) == 0) {
            cpu_merkle_node(cur, sib, f, next);
        } else {
            cpu_merkle_node(sib, cur, f, next);
        }

        for (int i = 0; i < P2_DIGEST; ++i) cur[i] = next[i];
        idx >>= 1;
    }

    const u64* root = &tree[(size_t)(2 * leaves - 2) * P2_DIGEST];

    for (int i = 0; i < P2_DIGEST; ++i) {
        if (cur[i] != root[i]) return false;
    }

    return true;
}

// -----------------------------
// GPU Poseidon2 + Merkle
// -----------------------------

__device__ __forceinline__ void gpu_poseidon2_perm(u64 state[P2_T]) {
    // Poseidon2 standard construction: initial external linear layer.
    {
        u64 initial_out[P2_T] = {};

        #pragma unroll
        for (int row = 0; row < P2_T; ++row) {
            u64 acc = 0;

            #pragma unroll
            for (int col = 0; col < P2_T; ++col) {
                acc = g64_add(
                    acc,
                    g64_mul(d_p2_matrix[row * P2_T + col], state[col])
                );
            }
            initial_out[row] = acc;
        }

        #pragma unroll
        for (int i = 0; i < P2_T; ++i) state[i] = initial_out[i];
    }

    constexpr int HALF = P2_RF / 2;

    for (int r = 0; r < HALF; ++r) {
        #pragma unroll
        for (int i = 0; i < P2_T; ++i) {
            state[i] = g64_add(state[i], d_p2_rc_ext[r * P2_T + i]);
        }

        #pragma unroll
        for (int i = 0; i < P2_T; ++i) {
            state[i] = g64_pow7(state[i]);
        }

        u64 out[P2_T] = {};

        #pragma unroll
        for (int row = 0; row < P2_T; ++row) {
            u64 acc = 0;

            #pragma unroll
            for (int col = 0; col < P2_T; ++col) {
                acc = g64_add(acc, g64_mul(d_p2_matrix[row * P2_T + col], state[col]));
            }

            out[row] = acc;
        }

        #pragma unroll
        for (int i = 0; i < P2_T; ++i) state[i] = out[i];
    }

    for (int r = 0; r < P2_RP; ++r) {
        state[0] = g64_add(state[0], d_p2_rc_int[r]);
        state[0] = g64_pow7(state[0]);

        u64 total = 0;

        #pragma unroll
        for (int i = 0; i < P2_T; ++i) {
            total = g64_add(total, state[i]);
        }

        u64 out[P2_T] = {};

        #pragma unroll
        for (int i = 0; i < P2_T; ++i) {
            out[i] = g64_add(g64_mul(d_p2_diag[i], state[i]), total);
        }

        #pragma unroll
        for (int i = 0; i < P2_T; ++i) state[i] = out[i];
    }

    for (int r = HALF; r < P2_RF; ++r) {
        #pragma unroll
        for (int i = 0; i < P2_T; ++i) {
            state[i] = g64_add(state[i], d_p2_rc_ext[r * P2_T + i]);
        }

        #pragma unroll
        for (int i = 0; i < P2_T; ++i) {
            state[i] = g64_pow7(state[i]);
        }

        u64 out[P2_T] = {};

        #pragma unroll
        for (int row = 0; row < P2_T; ++row) {
            u64 acc = 0;

            #pragma unroll
            for (int col = 0; col < P2_T; ++col) {
                acc = g64_add(acc, g64_mul(d_p2_matrix[row * P2_T + col], state[col]));
            }

            out[row] = acc;
        }

        #pragma unroll
        for (int i = 0; i < P2_T; ++i) state[i] = out[i];
    }
}

__device__ __forceinline__ void gpu_hash_row_leaf(
    const u64* matrix,
    int row,
    int cols,
    u64 digest[P2_DIGEST]
) {
    u64 state[P2_T] = {};
    state[P2_RATE] = d_p2_domains[DOMAIN_MERKLE_LEAF];

    int off = 0;

    while (off < cols) {
        int chunk = cols - off;
        if (chunk > P2_RATE) chunk = P2_RATE;

        for (int i = 0; i < chunk; ++i) {
            state[i] = g64_add(state[i], matrix[(size_t)row * cols + off + i]);
        }

        if (chunk < P2_RATE) {
            state[chunk] = g64_add(state[chunk], 1);
        }

        gpu_poseidon2_perm(state);
        off += chunk;
    }

    #pragma unroll
    for (int i = 0; i < P2_DIGEST; ++i) {
        digest[i] = state[i];
    }
}

__device__ __forceinline__ void gpu_hash_node(
    const u64 left[P2_DIGEST],
    const u64 right[P2_DIGEST],
    u64 parent[P2_DIGEST]
) {
    u64 state[P2_T] = {};

    #pragma unroll
    for (int i = 0; i < P2_DIGEST; ++i) {
        state[i] = left[i];
        state[P2_DIGEST + i] = right[i];
    }

    state[P2_RATE] = d_p2_domains[DOMAIN_MERKLE_NODE];

    gpu_poseidon2_perm(state);

    #pragma unroll
    for (int i = 0; i < P2_DIGEST; ++i) {
        parent[i] = state[i];
    }
}

__global__ void merkle_leaf_kernel(
    const u64* __restrict__ matrix,
    u64* __restrict__ out_leaves,
    int leaves,
    int cols
) {
    const int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= leaves) return;

    u64 d[P2_DIGEST];
    gpu_hash_row_leaf(matrix, idx, cols, d);

    #pragma unroll
    for (int i = 0; i < P2_DIGEST; ++i) {
        out_leaves[(size_t)idx * P2_DIGEST + i] = d[i];
    }
}

__global__ void merkle_reduce_kernel(
    const u64* __restrict__ in_layer,
    u64* __restrict__ out_layer,
    int out_nodes
) {
    const int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= out_nodes) return;

    u64 left[P2_DIGEST];
    u64 right[P2_DIGEST];
    u64 parent[P2_DIGEST];

    #pragma unroll
    for (int i = 0; i < P2_DIGEST; ++i) {
        left[i] = in_layer[(size_t)(2 * idx) * P2_DIGEST + i];
        right[i] = in_layer[(size_t)(2 * idx + 1) * P2_DIGEST + i];
    }

    gpu_hash_node(left, right, parent);

    #pragma unroll
    for (int i = 0; i < P2_DIGEST; ++i) {
        out_layer[(size_t)idx * P2_DIGEST + i] = parent[i];
    }
}

// -----------------------------
// GPU host runners
// -----------------------------

static void upload_poseidon2_constants(const FrozenPoseidon2& f) {
    HIP_CHECK(hipMemcpyToSymbol(HIP_SYMBOL(d_p2_rc_ext), f.rc_ext.data(), sizeof(u64) * f.rc_ext.size()));
    HIP_CHECK(hipMemcpyToSymbol(HIP_SYMBOL(d_p2_rc_int), f.rc_int.data(), sizeof(u64) * f.rc_int.size()));
    HIP_CHECK(hipMemcpyToSymbol(HIP_SYMBOL(d_p2_matrix), f.matrix.data(), sizeof(u64) * f.matrix.size()));
    HIP_CHECK(hipMemcpyToSymbol(HIP_SYMBOL(d_p2_diag), f.diag.data(), sizeof(u64) * f.diag.size()));
    HIP_CHECK(hipMemcpyToSymbol(HIP_SYMBOL(d_p2_domains), f.domains.data(), sizeof(u64) * f.domains.size()));
}

static float event_ms(hipEvent_t start, hipEvent_t stop) {
    float ms = 0.0f;
    HIP_CHECK(hipEventElapsedTime(&ms, start, stop));
    return ms;
}

struct GpuMerkleResult {
    std::vector<u64> tree_or_root;
    bool full_tree = false;

    float total_ms = 0.0f;
    float leaf_ms = 0.0f;
    float reduce_ms = 0.0f;
    std::vector<float> reduce_level_ms;
};

static GpuMerkleResult gpu_build_full_tree(
    const std::vector<u64>& matrix,
    int leaves,
    int cols
) {
    GpuMerkleResult result;
    result.full_tree = true;

    const int total_nodes = 2 * leaves - 1;
    result.tree_or_root.assign((size_t)total_nodes * P2_DIGEST, 0);

    u64* d_matrix = nullptr;
    u64* d_tree = nullptr;

    HIP_CHECK(hipMalloc(&d_matrix, matrix.size() * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_tree, result.tree_or_root.size() * sizeof(u64)));
    HIP_CHECK(hipMemcpy(d_matrix, matrix.data(), matrix.size() * sizeof(u64), hipMemcpyHostToDevice));

    hipEvent_t total_start, total_stop, stage_start, stage_stop;
    HIP_CHECK(hipEventCreate(&total_start));
    HIP_CHECK(hipEventCreate(&total_stop));
    HIP_CHECK(hipEventCreate(&stage_start));
    HIP_CHECK(hipEventCreate(&stage_stop));

    const int threads = 256;

    HIP_CHECK(hipEventRecord(total_start));

    const int leaf_blocks = (leaves + threads - 1) / threads;

    HIP_CHECK(hipEventRecord(stage_start));
    merkle_leaf_kernel<<<leaf_blocks, threads>>>(d_matrix, d_tree, leaves, cols);
    HIP_CHECK(hipGetLastError());
    HIP_CHECK(hipEventRecord(stage_stop));
    HIP_CHECK(hipEventSynchronize(stage_stop));
    result.leaf_ms = event_ms(stage_start, stage_stop);

    int cur_nodes = leaves;
    u64* cur_layer = d_tree;
    u64* next_layer = d_tree + (size_t)leaves * P2_DIGEST;

    while (cur_nodes > 1) {
        const int out_nodes = cur_nodes / 2;
        const int blocks = (out_nodes + threads - 1) / threads;

        HIP_CHECK(hipEventRecord(stage_start));
        merkle_reduce_kernel<<<blocks, threads>>>(cur_layer, next_layer, out_nodes);
        HIP_CHECK(hipGetLastError());
        HIP_CHECK(hipEventRecord(stage_stop));
        HIP_CHECK(hipEventSynchronize(stage_stop));

        const float ms = event_ms(stage_start, stage_stop);
        result.reduce_level_ms.push_back(ms);
        result.reduce_ms += ms;

        cur_layer = next_layer;
        next_layer += (size_t)out_nodes * P2_DIGEST;
        cur_nodes = out_nodes;
    }

    HIP_CHECK(hipEventRecord(total_stop));
    HIP_CHECK(hipEventSynchronize(total_stop));
    result.total_ms = event_ms(total_start, total_stop);

    HIP_CHECK(hipMemcpy(result.tree_or_root.data(), d_tree, result.tree_or_root.size() * sizeof(u64), hipMemcpyDeviceToHost));

    HIP_CHECK(hipEventDestroy(total_start));
    HIP_CHECK(hipEventDestroy(total_stop));
    HIP_CHECK(hipEventDestroy(stage_start));
    HIP_CHECK(hipEventDestroy(stage_stop));

    HIP_CHECK(hipFree(d_matrix));
    HIP_CHECK(hipFree(d_tree));

    return result;
}

static GpuMerkleResult gpu_build_root_only(
    const std::vector<u64>& matrix,
    int leaves,
    int cols
) {
    GpuMerkleResult result;
    result.full_tree = false;
    result.tree_or_root.assign(P2_DIGEST, 0);

    u64* d_matrix = nullptr;
    u64* d_a = nullptr;
    u64* d_b = nullptr;

    HIP_CHECK(hipMalloc(&d_matrix, matrix.size() * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_a, (size_t)leaves * P2_DIGEST * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_b, (size_t)leaves * P2_DIGEST * sizeof(u64)));

    HIP_CHECK(hipMemcpy(d_matrix, matrix.data(), matrix.size() * sizeof(u64), hipMemcpyHostToDevice));

    hipEvent_t total_start, total_stop, stage_start, stage_stop;
    HIP_CHECK(hipEventCreate(&total_start));
    HIP_CHECK(hipEventCreate(&total_stop));
    HIP_CHECK(hipEventCreate(&stage_start));
    HIP_CHECK(hipEventCreate(&stage_stop));

    const int threads = 256;

    HIP_CHECK(hipEventRecord(total_start));

    const int leaf_blocks = (leaves + threads - 1) / threads;

    HIP_CHECK(hipEventRecord(stage_start));
    merkle_leaf_kernel<<<leaf_blocks, threads>>>(d_matrix, d_a, leaves, cols);
    HIP_CHECK(hipGetLastError());
    HIP_CHECK(hipEventRecord(stage_stop));
    HIP_CHECK(hipEventSynchronize(stage_stop));
    result.leaf_ms = event_ms(stage_start, stage_stop);

    int cur_nodes = leaves;
    u64* cur = d_a;
    u64* next = d_b;

    while (cur_nodes > 1) {
        const int out_nodes = cur_nodes / 2;
        const int blocks = (out_nodes + threads - 1) / threads;

        HIP_CHECK(hipEventRecord(stage_start));
        merkle_reduce_kernel<<<blocks, threads>>>(cur, next, out_nodes);
        HIP_CHECK(hipGetLastError());
        HIP_CHECK(hipEventRecord(stage_stop));
        HIP_CHECK(hipEventSynchronize(stage_stop));

        const float ms = event_ms(stage_start, stage_stop);
        result.reduce_level_ms.push_back(ms);
        result.reduce_ms += ms;

        std::swap(cur, next);
        cur_nodes = out_nodes;
    }

    HIP_CHECK(hipEventRecord(total_stop));
    HIP_CHECK(hipEventSynchronize(total_stop));
    result.total_ms = event_ms(total_start, total_stop);

    HIP_CHECK(hipMemcpy(result.tree_or_root.data(), cur, P2_DIGEST * sizeof(u64), hipMemcpyDeviceToHost));

    HIP_CHECK(hipEventDestroy(total_start));
    HIP_CHECK(hipEventDestroy(total_stop));
    HIP_CHECK(hipEventDestroy(stage_start));
    HIP_CHECK(hipEventDestroy(stage_stop));

    HIP_CHECK(hipFree(d_matrix));
    HIP_CHECK(hipFree(d_a));
    HIP_CHECK(hipFree(d_b));

    return result;
}

// -----------------------------
// Test input generation
// -----------------------------

static u64 splitmix64(u64& x) {
    u64 z = (x += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static std::vector<u64> make_committed_matrix(int leaves, int cols) {
    std::vector<u64> matrix((size_t)leaves * cols);

    u64 seed = fnv1a64("QINGMING-MERKLE-G64-COMMITTED-MATRIX");

    for (size_t i = 0; i < matrix.size(); ++i) {
        // Test generator emits canonical field elements.
        // Merkle contract itself does not perform silent reduction.
        while (true) {
            u64 x = splitmix64(seed);
            if (x < G64_P) {
                matrix[i] = x;
                break;
            }
        }
    }

    return matrix;
}

// -----------------------------
// Correctness
// -----------------------------

static void run_correctness(
    const std::vector<u64>& matrix,
    const GpuMerkleResult& gpu,
    int leaves,
    int cols,
    int query,
    const FrozenPoseidon2& p2
) {
    if (!gpu.full_tree) throw std::runtime_error("correctness mode requires full tree");

    std::vector<u64> cpu_tree = cpu_build_merkle_tree(matrix, leaves, cols, p2);

    if (cpu_tree.size() != gpu.tree_or_root.size()) {
        throw std::runtime_error("CPU/GPU tree size mismatch");
    }

    for (size_t i = 0; i < cpu_tree.size(); ++i) {
        if (cpu_tree[i] != gpu.tree_or_root[i]) {
            std::ostringstream os;
            os << "CPU/GPU tree mismatch at element " << i
               << " cpu=" << hex64(cpu_tree[i])
               << " gpu=" << hex64(gpu.tree_or_root[i]);
            throw std::runtime_error(os.str());
        }
    }

    const bool opening_ok = cpu_verify_opening_from_tree(matrix, gpu.tree_or_root, leaves, cols, query, p2);
    if (!opening_ok) throw std::runtime_error("opening verification failed");

    std::vector<u64> tampered = matrix;
    tampered[(size_t)query * cols] = g64_add(tampered[(size_t)query * cols], 1);

    const bool tampered_ok = cpu_verify_opening_from_tree(tampered, gpu.tree_or_root, leaves, cols, query, p2);
    if (tampered_ok) throw std::runtime_error("tampered opening was accepted");

    std::vector<u64> bad = matrix;
    bad[0] = G64_P;

    bool rejected = false;
    try {
        check_canonical_matrix(bad);
    } catch (const std::runtime_error&) {
        rejected = true;
    }

    if (!rejected) throw std::runtime_error("non-canonical input was not rejected");
}


// Forward declaration used by FRI reporting.
static void print_digest(const char* name, const u64* d);


// -----------------------------
// QINGMING-FRI-G64
// -----------------------------
//
// FRI current contract:
//
//   input:
//     layer_0 matrix:
//       row-major canonical G64 field elements
//       layer_0[row * committed_columns + col]
//
//   commitment:
//     every FRI layer is committed with QINGMING-MERKLE-G64
//     root_r[4] = MerkleRoot(layer_r)
//
//   challenge:
//     beta_r = Poseidon2(TRANSCRIPT, root_r[4] || round_index)[0]
//
//   folding:
//     layer_{r+1}[i, c] = layer_r[2*i, c] + beta_r * layer_r[2*i + 1, c]
//
//   stop:
//     until rows == final_rows
//
// This file verifies the FRI commit/fold chain, not the final public proof format.

static void derive_fri_beta(
    const u64 root[P2_DIGEST],
    int round,
    const FrozenPoseidon2& p2,
    u64& beta
) {
    std::vector<u64> input;
    input.reserve(P2_DIGEST + 1);
    for (int i = 0; i < P2_DIGEST; ++i) input.push_back(root[i]);
    input.push_back((u64)round);

    u64 digest[P2_DIGEST];
    cpu_hash_elements(input, DOMAIN_TRANSCRIPT, p2, digest);
    beta = digest[0];
}

static std::vector<u64> cpu_fri_fold(
    const std::vector<u64>& cur,
    int rows,
    int cols,
    u64 beta
) {
    if (rows <= 1 || (rows & 1)) {
        throw std::runtime_error("FRI fold requires even rows > 1");
    }

    std::vector<u64> next((size_t)(rows / 2) * cols);

    for (int r = 0; r < rows / 2; ++r) {
        for (int c = 0; c < cols; ++c) {
            u64 even = cur[(size_t)(2 * r) * cols + c];
            u64 odd  = cur[(size_t)(2 * r + 1) * cols + c];
            next[(size_t)r * cols + c] = g64_add(even, g64_mul(beta, odd));
        }
    }

    return next;
}

struct CpuFriResult {
    std::vector<u64> roots;       // flattened roots, count = roots.size()/4
    std::vector<u64> betas;
    std::vector<u64> final_matrix;
    int rounds = 0;
};

static CpuFriResult cpu_fri_chain(
    const std::vector<u64>& layer0,
    int leaves,
    int cols,
    int final_rows,
    const FrozenPoseidon2& p2
) {
    if (!is_power_of_two_u64((u64)leaves)) throw std::runtime_error("FRI leaves must be power of two");
    if (!is_power_of_two_u64((u64)final_rows)) throw std::runtime_error("FRI final_rows must be power of two");
    if (final_rows <= 0 || final_rows > leaves) throw std::runtime_error("bad FRI final_rows");

    std::vector<u64> cur = layer0;
    int rows = leaves;
    int round = 0;

    CpuFriResult out;

    while (rows > final_rows) {
        std::vector<u64> tree = cpu_build_merkle_tree(cur, rows, cols, p2);
        const u64* root = &tree[(size_t)(2 * rows - 2) * P2_DIGEST];

        for (int i = 0; i < P2_DIGEST; ++i) out.roots.push_back(root[i]);

        u64 beta = 0;
        derive_fri_beta(root, round, p2, beta);
        out.betas.push_back(beta);

        cur = cpu_fri_fold(cur, rows, cols, beta);
        rows >>= 1;
        ++round;
    }

    // Commit final layer as well.
    std::vector<u64> final_tree = cpu_build_merkle_tree(cur, rows, cols, p2);
    const u64* final_root = &final_tree[(size_t)(2 * rows - 2) * P2_DIGEST];
    for (int i = 0; i < P2_DIGEST; ++i) out.roots.push_back(final_root[i]);

    out.final_matrix = std::move(cur);
    out.rounds = round;
    return out;
}

__global__ void fri_fold_kernel(
    const u64* __restrict__ cur,
    u64* __restrict__ next,
    int out_rows,
    int cols,
    u64 beta
) {
    const int idx = blockIdx.x * blockDim.x + threadIdx.x;
    const int total = out_rows * cols;
    if (idx >= total) return;

    const int r = idx / cols;
    const int c = idx - r * cols;

    const u64 even = cur[(size_t)(2 * r) * cols + c];
    const u64 odd  = cur[(size_t)(2 * r + 1) * cols + c];

    next[(size_t)r * cols + c] = g64_add(even, g64_mul(beta, odd));
}

struct GpuRootFromDeviceResult {
    u64 root[P2_DIGEST] = {};
    float total_ms = 0.0f;
    float leaf_ms = 0.0f;
    float reduce_ms = 0.0f;
    std::vector<float> reduce_level_ms;
};

static GpuRootFromDeviceResult gpu_merkle_root_from_device_matrix(
    const u64* d_matrix,
    int rows,
    int cols
) {
    GpuRootFromDeviceResult result;

    u64* d_a = nullptr;
    u64* d_b = nullptr;

    HIP_CHECK(hipMalloc(&d_a, (size_t)rows * P2_DIGEST * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_b, (size_t)rows * P2_DIGEST * sizeof(u64)));

    hipEvent_t total_start, total_stop, stage_start, stage_stop;
    HIP_CHECK(hipEventCreate(&total_start));
    HIP_CHECK(hipEventCreate(&total_stop));
    HIP_CHECK(hipEventCreate(&stage_start));
    HIP_CHECK(hipEventCreate(&stage_stop));

    const int threads = 256;

    HIP_CHECK(hipEventRecord(total_start));

    const int leaf_blocks = (rows + threads - 1) / threads;

    HIP_CHECK(hipEventRecord(stage_start));
    merkle_leaf_kernel<<<leaf_blocks, threads>>>(d_matrix, d_a, rows, cols);
    HIP_CHECK(hipGetLastError());
    HIP_CHECK(hipEventRecord(stage_stop));
    HIP_CHECK(hipEventSynchronize(stage_stop));
    result.leaf_ms = event_ms(stage_start, stage_stop);

    int cur_nodes = rows;
    u64* cur = d_a;
    u64* next = d_b;

    while (cur_nodes > 1) {
        const int out_nodes = cur_nodes / 2;
        const int blocks = (out_nodes + threads - 1) / threads;

        HIP_CHECK(hipEventRecord(stage_start));
        merkle_reduce_kernel<<<blocks, threads>>>(cur, next, out_nodes);
        HIP_CHECK(hipGetLastError());
        HIP_CHECK(hipEventRecord(stage_stop));
        HIP_CHECK(hipEventSynchronize(stage_stop));

        const float ms = event_ms(stage_start, stage_stop);
        result.reduce_level_ms.push_back(ms);
        result.reduce_ms += ms;

        std::swap(cur, next);
        cur_nodes = out_nodes;
    }

    HIP_CHECK(hipEventRecord(total_stop));
    HIP_CHECK(hipEventSynchronize(total_stop));
    result.total_ms = event_ms(total_start, total_stop);

    HIP_CHECK(hipMemcpy(result.root, cur, P2_DIGEST * sizeof(u64), hipMemcpyDeviceToHost));

    HIP_CHECK(hipEventDestroy(total_start));
    HIP_CHECK(hipEventDestroy(total_stop));
    HIP_CHECK(hipEventDestroy(stage_start));
    HIP_CHECK(hipEventDestroy(stage_stop));

    HIP_CHECK(hipFree(d_a));
    HIP_CHECK(hipFree(d_b));

    return result;
}

struct GpuFriResult {
    std::vector<u64> roots;       // flattened roots
    std::vector<u64> betas;
    std::vector<u64> final_matrix;

    int rounds = 0;
    int final_rows = 1;

    float total_ms = 0.0f;
    float merkle_ms = 0.0f;
    float fold_ms = 0.0f;
    std::vector<float> layer_merkle_ms;
    std::vector<float> layer_fold_ms;
};

static GpuFriResult gpu_fri_chain(
    const std::vector<u64>& layer0,
    int leaves,
    int cols,
    int final_rows,
    const FrozenPoseidon2& p2,
    bool copy_final_matrix
) {
    if (!is_power_of_two_u64((u64)leaves)) throw std::runtime_error("FRI leaves must be power of two");
    if (!is_power_of_two_u64((u64)final_rows)) throw std::runtime_error("FRI final_rows must be power of two");
    if (final_rows <= 0 || final_rows > leaves) throw std::runtime_error("bad FRI final_rows");

    GpuFriResult out;
    out.final_rows = final_rows;

    u64* d_cur = nullptr;
    u64* d_next = nullptr;

    const size_t layer0_bytes = layer0.size() * sizeof(u64);
    HIP_CHECK(hipMalloc(&d_cur, layer0_bytes));
    HIP_CHECK(hipMalloc(&d_next, layer0_bytes));
    HIP_CHECK(hipMemcpy(d_cur, layer0.data(), layer0_bytes, hipMemcpyHostToDevice));

    hipEvent_t fold_start, fold_stop;
    HIP_CHECK(hipEventCreate(&fold_start));
    HIP_CHECK(hipEventCreate(&fold_stop));

    int rows = leaves;
    int round = 0;

    while (rows > final_rows) {
        GpuRootFromDeviceResult root = gpu_merkle_root_from_device_matrix(d_cur, rows, cols);

        for (int i = 0; i < P2_DIGEST; ++i) out.roots.push_back(root.root[i]);

        out.layer_merkle_ms.push_back(root.total_ms);
        out.merkle_ms += root.total_ms;

        u64 beta = 0;
        derive_fri_beta(root.root, round, p2, beta);
        out.betas.push_back(beta);

        const int out_rows = rows / 2;
        const int total_out = out_rows * cols;
        const int threads = 256;
        const int blocks = (total_out + threads - 1) / threads;

        HIP_CHECK(hipEventRecord(fold_start));
        fri_fold_kernel<<<blocks, threads>>>(d_cur, d_next, out_rows, cols, beta);
        HIP_CHECK(hipGetLastError());
        HIP_CHECK(hipEventRecord(fold_stop));
        HIP_CHECK(hipEventSynchronize(fold_stop));

        float fms = event_ms(fold_start, fold_stop);
        out.layer_fold_ms.push_back(fms);
        out.fold_ms += fms;

        std::swap(d_cur, d_next);
        rows = out_rows;
        ++round;
    }

    // Commit final layer.
    GpuRootFromDeviceResult final_root = gpu_merkle_root_from_device_matrix(d_cur, rows, cols);
    for (int i = 0; i < P2_DIGEST; ++i) out.roots.push_back(final_root.root[i]);
    out.layer_merkle_ms.push_back(final_root.total_ms);
    out.merkle_ms += final_root.total_ms;

    out.rounds = round;
    out.total_ms = out.merkle_ms + out.fold_ms;

    if (copy_final_matrix) {
        out.final_matrix.assign((size_t)rows * cols, 0);
        HIP_CHECK(hipMemcpy(out.final_matrix.data(), d_cur, out.final_matrix.size() * sizeof(u64), hipMemcpyDeviceToHost));
    }

    HIP_CHECK(hipEventDestroy(fold_start));
    HIP_CHECK(hipEventDestroy(fold_stop));
    HIP_CHECK(hipFree(d_cur));
    HIP_CHECK(hipFree(d_next));

    return out;
}

static void run_fri_correctness(
    const std::vector<u64>& layer0,
    int leaves,
    int cols,
    int final_rows,
    const FrozenPoseidon2& p2,
    const GpuFriResult& gpu
) {
    CpuFriResult cpu = cpu_fri_chain(layer0, leaves, cols, final_rows, p2);

    if (cpu.roots.size() != gpu.roots.size()) {
        throw std::runtime_error("FRI roots count mismatch");
    }

    for (size_t i = 0; i < cpu.roots.size(); ++i) {
        if (cpu.roots[i] != gpu.roots[i]) {
            std::ostringstream os;
            os << "FRI root mismatch at element " << i
               << " cpu=" << hex64(cpu.roots[i])
               << " gpu=" << hex64(gpu.roots[i]);
            throw std::runtime_error(os.str());
        }
    }

    if (cpu.betas.size() != gpu.betas.size()) {
        throw std::runtime_error("FRI beta count mismatch");
    }

    for (size_t i = 0; i < cpu.betas.size(); ++i) {
        if (cpu.betas[i] != gpu.betas[i]) {
            std::ostringstream os;
            os << "FRI beta mismatch at round " << i
               << " cpu=" << hex64(cpu.betas[i])
               << " gpu=" << hex64(gpu.betas[i]);
            throw std::runtime_error(os.str());
        }
    }

    if (cpu.final_matrix.size() != gpu.final_matrix.size()) {
        throw std::runtime_error("FRI final matrix size mismatch");
    }

    for (size_t i = 0; i < cpu.final_matrix.size(); ++i) {
        if (cpu.final_matrix[i] != gpu.final_matrix[i]) {
            std::ostringstream os;
            os << "FRI final matrix mismatch at element " << i
               << " cpu=" << hex64(cpu.final_matrix[i])
               << " gpu=" << hex64(gpu.final_matrix[i]);
            throw std::runtime_error(os.str());
        }
    }
}

static void print_fri_layers(const std::vector<float>& ms) {
    std::cout << "[";
    for (size_t i = 0; i < ms.size(); ++i) {
        if (i) std::cout << ", ";
        std::cout << std::fixed << std::setprecision(3) << ms[i];
    }
    std::cout << "]";
}

static void report_fri(
    const char* title,
    const FrozenPoseidon2& p2,
    const Options& opt,
    const GpuFriResult& fri,
    bool correctness_done
) {
    const u64 committed_elements = (u64)opt.leaf_count * (u64)opt.committed_columns;
    const int root_count = (int)(fri.roots.size() / P2_DIGEST);
    const u64* final_root = &fri.roots[(size_t)(root_count - 1) * P2_DIGEST];

    // Sum theoretical Merkle/Folding work over layers including final commit.
    u64 total_poseidon2_permutations = 0;
    u64 total_merkle_hash_objects = 0;
    u64 total_fold_elements = 0;

    int rows = opt.leaf_count;
    const u64 leaf_perms_per_leaf =
        ((u64)opt.committed_columns + (u64)P2_RATE - 1) / (u64)P2_RATE;

    while (rows >= opt.final_rows) {
        total_merkle_hash_objects += (u64)rows + (u64)(rows - 1);
        total_poseidon2_permutations += (u64)rows * leaf_perms_per_leaf + (u64)(rows - 1);

        if (rows == opt.final_rows) break;
        total_fold_elements += (u64)(rows / 2) * (u64)opt.committed_columns;
        rows >>= 1;
    }

    const double sec = (double)fri.total_ms / 1000.0;
    const double fri_poseidon2_permutations_per_sec = (double)total_poseidon2_permutations / sec;
    const double fri_fold_elements_per_sec = (double)total_fold_elements / sec;

    std::cout << title << "\n";
    std::cout << "status: PASS\n";
    std::cout << "operator: fri-g64-commit-fold-generic-layered-merkle\n";
    std::cout << "field: Goldilocks/G64\n";
    std::cout << "p: " << G64_P << "\n";
    std::cout << "hash: QINGMING-POSEIDON2-G64\n";
    std::cout << "merkle_operator: generic-layered-final\n";
    std::cout << "poseidon2_params_fingerprint: " << hex64(p2.params_fingerprint) << "\n";
    std::cout << "poseidon2_test_vectors_fingerprint: " << hex64(p2.vectors_fingerprint) << "\n";
    std::cout << "layer0_rows: " << opt.leaf_count << "\n";
    std::cout << "final_rows: " << opt.final_rows << "\n";
    std::cout << "fri_rounds: " << fri.rounds << "\n";
    std::cout << "fri_root_count: " << root_count << "\n";
    std::cout << "committed_columns: " << opt.committed_columns << "\n";
    std::cout << "committed_elements_layer0: " << committed_elements << "\n";
    std::cout << "folding: next[i,c] = even + beta * odd\n";
    std::cout << "challenge: beta = Poseidon2(TRANSCRIPT, root[4] || round)[0]\n";
    std::cout << "gpu_total_ms: " << std::fixed << std::setprecision(3) << fri.total_ms << "\n";
    std::cout << "gpu_merkle_ms: " << std::fixed << std::setprecision(3) << fri.merkle_ms << "\n";
    std::cout << "gpu_fold_ms: " << std::fixed << std::setprecision(3) << fri.fold_ms << "\n";
    std::cout << "fri_layer_merkle_ms: ";
    print_fri_layers(fri.layer_merkle_ms);
    std::cout << "\n";
    std::cout << "fri_layer_fold_ms: ";
    print_fri_layers(fri.layer_fold_ms);
    std::cout << "\n";
    std::cout << "fri_total_merkle_hash_objects: " << total_merkle_hash_objects << "\n";
    std::cout << "fri_total_poseidon2_permutations: " << total_poseidon2_permutations << "\n";
    std::cout << "fri_total_fold_elements: " << total_fold_elements << "\n";
    std::cout << "fri_poseidon2_permutations_per_sec: " << std::fixed << std::setprecision(2) << fri_poseidon2_permutations_per_sec << "\n";
    std::cout << "fri_fold_elements_per_sec: " << std::fixed << std::setprecision(2) << fri_fold_elements_per_sec << "\n";
    std::cout << "fri_roots_fingerprint: " << hex64(fingerprint_values(fri.roots, "QINGMING-FRI-G64-ROOTS")) << "\n";
    std::cout << "fri_betas_fingerprint: " << hex64(fingerprint_values(fri.betas, "QINGMING-FRI-G64-BETAS")) << "\n";
    if (!fri.final_matrix.empty()) {
        std::cout << "fri_final_matrix_fingerprint: " << hex64(fingerprint_values(fri.final_matrix, "QINGMING-FRI-G64-FINAL-MATRIX")) << "\n";
    } else {
        std::cout << "fri_final_matrix_fingerprint: SKIPPED\n";
    }
    std::cout << "cpu_gpu_fri_roots_compare: " << (correctness_done ? "PASS" : "SKIPPED") << "\n";
    std::cout << "cpu_gpu_fri_betas_compare: " << (correctness_done ? "PASS" : "SKIPPED") << "\n";
    std::cout << "cpu_gpu_final_matrix_compare: " << (correctness_done ? "PASS" : "SKIPPED") << "\n";
    print_digest("final_root", final_root);
}

static void report_fri_sweep_row(
    int scale_k,
    int leaves,
    int cols,
    int final_rows,
    const GpuFriResult& fri
) {
    const int root_count = (int)(fri.roots.size() / P2_DIGEST);
    const u64* final_root = &fri.roots[(size_t)(root_count - 1) * P2_DIGEST];

    std::cout
        << scale_k << ","
        << leaves << ","
        << cols << ","
        << ((u64)leaves * (u64)cols) << ","
        << final_rows << ","
        << fri.rounds << ","
        << root_count << ","
        << std::fixed << std::setprecision(3) << fri.total_ms << ","
        << std::fixed << std::setprecision(3) << fri.merkle_ms << ","
        << std::fixed << std::setprecision(3) << fri.fold_ms << ","
        << hex64(final_root[0]) << ";"
        << hex64(final_root[1]) << ";"
        << hex64(final_root[2]) << ";"
        << hex64(final_root[3])
        << "\n";
}


// -----------------------------
// Reporting
// -----------------------------

static void print_reduce_levels(const std::vector<float>& xs) {
    std::cout << "reduce_level_ms: [";
    for (size_t i = 0; i < xs.size(); ++i) {
        if (i) std::cout << ", ";
        std::cout << std::fixed << std::setprecision(3) << xs[i];
    }
    std::cout << "]\n";
}

static void print_digest(const char* name, const u64* d) {
    std::cout << name << ": [";
    for (int i = 0; i < P2_DIGEST; ++i) {
        if (i) std::cout << ", ";
        std::cout << hex64(d[i]);
    }
    std::cout << "]\n";
}

static void compute_metrics(
    int leaves,
    int cols,
    u64& committed_elements,
    u64& merkle_leaf_objects,
    u64& merkle_node_objects,
    u64& merkle_hash_objects,
    u64& leaf_absorb_permutations_per_leaf,
    u64& poseidon2_leaf_permutations,
    u64& poseidon2_node_permutations,
    u64& poseidon2_total_permutations
) {
    const u64 L = (u64)leaves;
    const u64 C = (u64)cols;

    committed_elements = L * C;
    merkle_leaf_objects = L;
    merkle_node_objects = L - 1;
    merkle_hash_objects = merkle_leaf_objects + merkle_node_objects;

    leaf_absorb_permutations_per_leaf = (C + (u64)P2_RATE - 1) / (u64)P2_RATE;
    poseidon2_leaf_permutations = L * leaf_absorb_permutations_per_leaf;
    poseidon2_node_permutations = merkle_node_objects;
    poseidon2_total_permutations = poseidon2_leaf_permutations + poseidon2_node_permutations;
}

static const u64* result_root_ptr(const GpuMerkleResult& result, int leaves) {
    if (result.full_tree) {
        return &result.tree_or_root[(size_t)(2 * leaves - 2) * P2_DIGEST];
    }
    return result.tree_or_root.data();
}

static void report_full(
    const char* title,
    const FrozenPoseidon2& p2,
    const Options& opt,
    const GpuMerkleResult& result,
    bool correctness_done
) {
    u64 committed_elements = 0;
    u64 merkle_leaf_objects = 0;
    u64 merkle_node_objects = 0;
    u64 merkle_hash_objects = 0;
    u64 leaf_absorb_permutations_per_leaf = 0;
    u64 poseidon2_leaf_permutations = 0;
    u64 poseidon2_node_permutations = 0;
    u64 poseidon2_total_permutations = 0;

    compute_metrics(
        opt.leaf_count,
        opt.committed_columns,
        committed_elements,
        merkle_leaf_objects,
        merkle_node_objects,
        merkle_hash_objects,
        leaf_absorb_permutations_per_leaf,
        poseidon2_leaf_permutations,
        poseidon2_node_permutations,
        poseidon2_total_permutations
    );

    const double sec = (double)result.total_ms / 1000.0;

    const double merkle_hash_objects_per_sec = (double)merkle_hash_objects / sec;
    const double poseidon2_permutations_per_sec = (double)poseidon2_total_permutations / sec;
    const double committed_elements_per_sec = (double)committed_elements / sec;

    const u64* root = result_root_ptr(result, opt.leaf_count);

    std::cout << title << "\n";
    std::cout << "status: PASS\n";
    std::cout << "operator: generic-layered-final\n";
    std::cout << "field: Goldilocks/G64\n";
    std::cout << "p: " << G64_P << "\n";
    std::cout << "hash: QINGMING-POSEIDON2-G64\n";
    std::cout << "poseidon2_params_fingerprint: " << hex64(p2.params_fingerprint) << "\n";
    std::cout << "poseidon2_test_vectors_fingerprint: " << hex64(p2.vectors_fingerprint) << "\n";
    std::cout << "tree_arity: 2\n";
    std::cout << "leaf_count: " << opt.leaf_count << "\n";
    std::cout << "tree_height: " << log2_u64((u64)opt.leaf_count) << "\n";
    std::cout << "committed_columns: " << opt.committed_columns << "\n";
    std::cout << "committed_elements: " << committed_elements << "\n";
    std::cout << "input_layout: row-major values[row * committed_columns + col]\n";
    std::cout << "digest_len: " << P2_DIGEST << "\n";

    std::cout << "gpu_total_ms: " << std::fixed << std::setprecision(3) << result.total_ms << "\n";
    std::cout << "gpu_leaf_ms: " << std::fixed << std::setprecision(3) << result.leaf_ms << "\n";
    std::cout << "gpu_reduce_ms: " << std::fixed << std::setprecision(3) << result.reduce_ms << "\n";
    print_reduce_levels(result.reduce_level_ms);

    std::cout << "merkle_leaf_objects: " << merkle_leaf_objects << "\n";
    std::cout << "merkle_node_objects: " << merkle_node_objects << "\n";
    std::cout << "merkle_hash_objects: " << merkle_hash_objects << "\n";
    std::cout << "leaf_absorb_permutations_per_leaf: " << leaf_absorb_permutations_per_leaf << "\n";
    std::cout << "poseidon2_leaf_permutations: " << poseidon2_leaf_permutations << "\n";
    std::cout << "poseidon2_node_permutations: " << poseidon2_node_permutations << "\n";
    std::cout << "poseidon2_total_permutations: " << poseidon2_total_permutations << "\n";

    std::cout << "merkle_hash_objects_per_sec: " << std::fixed << std::setprecision(2) << merkle_hash_objects_per_sec << "\n";
    std::cout << "poseidon2_permutations_per_sec: " << std::fixed << std::setprecision(2) << poseidon2_permutations_per_sec << "\n";
    std::cout << "committed_elements_per_sec: " << std::fixed << std::setprecision(2) << committed_elements_per_sec << "\n";

    if (result.full_tree) {
        std::cout << "gpu_tree_fingerprint: " << hex64(fingerprint_values(result.tree_or_root, "QINGMING-MERKLE-G64-GPU-TREE")) << "\n";
    } else {
        std::cout << "gpu_root_fingerprint: " << hex64(fingerprint_values(result.tree_or_root, "QINGMING-MERKLE-G64-GPU-ROOT")) << "\n";
    }

    std::cout << "cpu_gpu_tree_compare: " << (correctness_done ? "PASS" : "SKIPPED") << "\n";
    std::cout << "opening_query_index: " << opt.query_index << "\n";
    std::cout << "opening_verify: " << (correctness_done ? "PASS" : "SKIPPED") << "\n";
    std::cout << "tamper_opening_reject: " << (correctness_done ? "PASS" : "SKIPPED") << "\n";
    std::cout << "non_canonical_input_reject: " << (correctness_done ? "PASS" : "SKIPPED") << "\n";
    print_digest("root", root);
}

static void report_sweep_row(
    int scale_k,
    int leaves,
    int cols,
    const GpuMerkleResult& result
) {
    u64 committed_elements = 0;
    u64 merkle_leaf_objects = 0;
    u64 merkle_node_objects = 0;
    u64 merkle_hash_objects = 0;
    u64 leaf_absorb_permutations_per_leaf = 0;
    u64 poseidon2_leaf_permutations = 0;
    u64 poseidon2_node_permutations = 0;
    u64 poseidon2_total_permutations = 0;

    compute_metrics(
        leaves,
        cols,
        committed_elements,
        merkle_leaf_objects,
        merkle_node_objects,
        merkle_hash_objects,
        leaf_absorb_permutations_per_leaf,
        poseidon2_leaf_permutations,
        poseidon2_node_permutations,
        poseidon2_total_permutations
    );

    const double sec = (double)result.total_ms / 1000.0;
    const double poseidon2_permutations_per_sec = (double)poseidon2_total_permutations / sec;
    const double committed_elements_per_sec = (double)committed_elements / sec;

    const u64* root = result_root_ptr(result, leaves);

    std::cout
        << scale_k << ","
        << leaves << ","
        << cols << ","
        << committed_elements << ","
        << log2_u64((u64)leaves) << ","
        << std::fixed << std::setprecision(3) << result.total_ms << ","
        << std::fixed << std::setprecision(3) << result.leaf_ms << ","
        << std::fixed << std::setprecision(3) << result.reduce_ms << ","
        << poseidon2_total_permutations << ","
        << std::fixed << std::setprecision(2) << poseidon2_permutations_per_sec << ","
        << std::fixed << std::setprecision(2) << committed_elements_per_sec << ","
        << hex64(root[0]) << ";"
        << hex64(root[1]) << ";"
        << hex64(root[2]) << ";"
        << hex64(root[3])
        << "\n";
}

// -----------------------------
// QINGMING-G64-NTT FAST interface
// -----------------------------
//
// Current FAST interface contract:
//
//   input:
//     device-resident row-major matrix
//     matrix[row * committed_columns + col]
//
//   transform:
//     forward radix-2 NTT along the row dimension for every committed column
//
//   output:
//     same device buffer, in-place
//
//   root:
//     Goldilocks primitive 2^32 root:
//       0x185629dcda58878c
//
// This is the single E2E entry point used before FRI.
// The large matrix enters GPU once and remains device-resident through FRI.

static constexpr u64 G64_ROOT_2_32 = 0x185629dcda58878cULL;

static u64 g64_pow_u64(u64 base, u64 exp) {
    u64 acc = 1;

    while (exp) {
        if (exp & 1) acc = g64_mul(acc, base);
        base = g64_mul(base, base);
        exp >>= 1;
    }

    return acc;
}

static void check_ntt_root_contract(int rows) {
    if (!is_power_of_two_u64((u64)rows)) throw std::runtime_error("NTT rows must be power of two");
    if (rows <= 0) throw std::runtime_error("NTT rows must be positive");
    if ((u64)rows > (1ULL << 32)) throw std::runtime_error("NTT rows exceed Goldilocks 2^32 root domain");

    const u64 root_pow = g64_pow_u64(G64_ROOT_2_32, (1ULL << 32));
    if (root_pow != 1) throw std::runtime_error("G64_ROOT_2_32^2^32 != 1");

    const u64 half_pow = g64_pow_u64(G64_ROOT_2_32, (1ULL << 31));
    if (half_pow == 1) throw std::runtime_error("G64_ROOT_2_32 is not primitive for 2^32 domain");
}

static u64 bit_reverse_host(u64 x, int bits) {
    u64 y = 0;

    for (int i = 0; i < bits; ++i) {
        y = (y << 1) | (x & 1);
        x >>= 1;
    }

    return y;
}

static void cpu_ntt_columns_inplace(
    std::vector<u64>& matrix,
    int rows,
    int cols
) {
    check_canonical_matrix(matrix);
    check_ntt_root_contract(rows);

    const int bits = log2_u64((u64)rows);

    for (int r = 0; r < rows; ++r) {
        const int rr = (int)bit_reverse_host((u64)r, bits);

        if (r < rr) {
            for (int c = 0; c < cols; ++c) {
                std::swap(matrix[(size_t)r * cols + c], matrix[(size_t)rr * cols + c]);
            }
        }
    }

    const u64 omega_n = g64_pow_u64(G64_ROOT_2_32, (1ULL << 32) / (u64)rows);

    for (int len = 2; len <= rows; len <<= 1) {
        const int half = len >> 1;
        const u64 wlen = g64_pow_u64(omega_n, (u64)rows / (u64)len);

        for (int block = 0; block < rows; block += len) {
            u64 w = 1;

            for (int j = 0; j < half; ++j) {
                for (int c = 0; c < cols; ++c) {
                    const size_t p0 = (size_t)(block + j) * cols + c;
                    const size_t p1 = (size_t)(block + j + half) * cols + c;

                    const u64 u = matrix[p0];
                    const u64 v = g64_mul(matrix[p1], w);

                    matrix[p0] = g64_add(u, v);
                    matrix[p1] = g64_sub(u, v);
                }

                w = g64_mul(w, wlen);
            }
        }
    }
}

static std::vector<u64> make_ntt_stage_twiddles(int rows) {
    check_ntt_root_contract(rows);

    std::vector<u64> twiddles;
    twiddles.reserve((size_t)rows - 1);

    const u64 omega_n = g64_pow_u64(G64_ROOT_2_32, (1ULL << 32) / (u64)rows);

    for (int len = 2; len <= rows; len <<= 1) {
        const int half = len >> 1;
        const u64 wlen = g64_pow_u64(omega_n, (u64)rows / (u64)len);

        u64 w = 1;
        for (int j = 0; j < half; ++j) {
            twiddles.push_back(w);
            w = g64_mul(w, wlen);
        }
    }

    return twiddles;
}

__device__ __forceinline__ u64 bit_reverse_device(u64 x, int bits) {
    u64 y = 0;

    for (int i = 0; i < bits; ++i) {
        y = (y << 1) | (x & 1);
        x >>= 1;
    }

    return y;
}

__global__ void ntt_bit_reverse_rows_kernel(
    u64* __restrict__ matrix,
    int rows,
    int cols,
    int bits
) {
    const int idx = blockIdx.x * blockDim.x + threadIdx.x;
    const int total = rows * cols;
    if (idx >= total) return;

    const int r = idx / cols;
    const int c = idx - r * cols;

    const int rr = (int)bit_reverse_device((u64)r, bits);

    if (r < rr) {
        u64* a = &matrix[(size_t)r * cols + c];
        u64* b = &matrix[(size_t)rr * cols + c];

        const u64 tmp = *a;
        *a = *b;
        *b = tmp;
    }
}

__global__ void ntt_stage_rows_kernel(
    u64* __restrict__ matrix,
    const u64* __restrict__ twiddles,
    int rows,
    int cols,
    int len,
    int twiddle_offset
) {
    const int half = len >> 1;
    const int idx = blockIdx.x * blockDim.x + threadIdx.x;
    const int total = (rows >> 1) * cols;
    if (idx >= total) return;

    const int c = idx % cols;
    const int t = idx / cols;

    const int j = t % half;
    const int group = t / half;

    const int row0 = group * len + j;
    const int row1 = row0 + half;

    const u64 w = twiddles[twiddle_offset + j];

    const size_t p0 = (size_t)row0 * cols + c;
    const size_t p1 = (size_t)row1 * cols + c;

    const u64 u = matrix[p0];
    const u64 v = g64_mul(matrix[p1], w);

    matrix[p0] = g64_add(u, v);
    matrix[p1] = g64_sub(u, v);
}

struct GpuNttResult {
    float total_ms = 0.0f;
    float bit_reverse_ms = 0.0f;
    float stages_ms = 0.0f;
    std::vector<float> stage_ms;
};

static GpuNttResult gpu_ntt_fast_inplace(
    u64* d_matrix,
    int rows,
    int cols
) {
    check_ntt_root_contract(rows);

    GpuNttResult result;

    std::vector<u64> twiddles = make_ntt_stage_twiddles(rows);
    u64* d_twiddles = nullptr;
    HIP_CHECK(hipMalloc(&d_twiddles, twiddles.size() * sizeof(u64)));
    HIP_CHECK(hipMemcpy(d_twiddles, twiddles.data(), twiddles.size() * sizeof(u64), hipMemcpyHostToDevice));

    hipEvent_t total_start, total_stop, stage_start, stage_stop;
    HIP_CHECK(hipEventCreate(&total_start));
    HIP_CHECK(hipEventCreate(&total_stop));
    HIP_CHECK(hipEventCreate(&stage_start));
    HIP_CHECK(hipEventCreate(&stage_stop));

    const int threads = 256;
    const int bits = log2_u64((u64)rows);

    HIP_CHECK(hipEventRecord(total_start));

    const int br_total = rows * cols;
    const int br_blocks = (br_total + threads - 1) / threads;

    HIP_CHECK(hipEventRecord(stage_start));
    ntt_bit_reverse_rows_kernel<<<br_blocks, threads>>>(d_matrix, rows, cols, bits);
    HIP_CHECK(hipGetLastError());
    HIP_CHECK(hipEventRecord(stage_stop));
    HIP_CHECK(hipEventSynchronize(stage_stop));
    result.bit_reverse_ms = event_ms(stage_start, stage_stop);

    int twiddle_offset = 0;

    for (int len = 2; len <= rows; len <<= 1) {
        const int stage_total = (rows >> 1) * cols;
        const int stage_blocks = (stage_total + threads - 1) / threads;

        HIP_CHECK(hipEventRecord(stage_start));
        ntt_stage_rows_kernel<<<stage_blocks, threads>>>(d_matrix, d_twiddles, rows, cols, len, twiddle_offset);
        HIP_CHECK(hipGetLastError());
        HIP_CHECK(hipEventRecord(stage_stop));
        HIP_CHECK(hipEventSynchronize(stage_stop));

        const float ms = event_ms(stage_start, stage_stop);
        result.stage_ms.push_back(ms);
        result.stages_ms += ms;

        twiddle_offset += (len >> 1);
    }

    HIP_CHECK(hipEventRecord(total_stop));
    HIP_CHECK(hipEventSynchronize(total_stop));
    result.total_ms = event_ms(total_start, total_stop);

    HIP_CHECK(hipEventDestroy(total_start));
    HIP_CHECK(hipEventDestroy(total_stop));
    HIP_CHECK(hipEventDestroy(stage_start));
    HIP_CHECK(hipEventDestroy(stage_stop));

    HIP_CHECK(hipFree(d_twiddles));

    return result;
}

// -----------------------------
// Device-resident FRI chain for E2E
// -----------------------------

__global__ void fri_beta_kernel(
    const u64* __restrict__ roots,
    u64* __restrict__ betas,
    int round
) {
    if (blockIdx.x != 0 || threadIdx.x != 0) return;

    u64 state[P2_T] = {};

    #pragma unroll
    for (int i = 0; i < P2_DIGEST; ++i) {
        state[i] = roots[(size_t)round * P2_DIGEST + i];
    }

    state[P2_DIGEST] = (u64)round;
    state[P2_DIGEST + 1] = g64_add(state[P2_DIGEST + 1], 1);
    state[P2_RATE] = d_p2_domains[DOMAIN_TRANSCRIPT];

    gpu_poseidon2_perm(state);

    betas[round] = state[0];
}

__global__ void fri_fold_kernel_device_beta(
    const u64* __restrict__ cur,
    u64* __restrict__ next,
    const u64* __restrict__ betas,
    int round,
    int out_rows,
    int cols
) {
    const int idx = blockIdx.x * blockDim.x + threadIdx.x;
    const int total = out_rows * cols;
    if (idx >= total) return;

    const int r = idx / cols;
    const int c = idx - r * cols;

    const u64 beta = betas[round];

    const u64 even = cur[(size_t)(2 * r) * cols + c];
    const u64 odd  = cur[(size_t)(2 * r + 1) * cols + c];

    next[(size_t)r * cols + c] = g64_add(even, g64_mul(beta, odd));
}

struct GpuRootDeviceResult {
    float total_ms = 0.0f;
    float leaf_ms = 0.0f;
    float reduce_ms = 0.0f;
    std::vector<float> reduce_level_ms;
};

static GpuRootDeviceResult gpu_merkle_root_to_device(
    const u64* d_matrix,
    int rows,
    int cols,
    u64* d_root_out
) {
    GpuRootDeviceResult result;

    u64* d_a = nullptr;
    u64* d_b = nullptr;

    HIP_CHECK(hipMalloc(&d_a, (size_t)rows * P2_DIGEST * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_b, (size_t)rows * P2_DIGEST * sizeof(u64)));

    hipEvent_t total_start, total_stop, stage_start, stage_stop;
    HIP_CHECK(hipEventCreate(&total_start));
    HIP_CHECK(hipEventCreate(&total_stop));
    HIP_CHECK(hipEventCreate(&stage_start));
    HIP_CHECK(hipEventCreate(&stage_stop));

    const int threads = 256;

    HIP_CHECK(hipEventRecord(total_start));

    const int leaf_blocks = (rows + threads - 1) / threads;

    HIP_CHECK(hipEventRecord(stage_start));
    merkle_leaf_kernel<<<leaf_blocks, threads>>>(d_matrix, d_a, rows, cols);
    HIP_CHECK(hipGetLastError());
    HIP_CHECK(hipEventRecord(stage_stop));
    HIP_CHECK(hipEventSynchronize(stage_stop));
    result.leaf_ms = event_ms(stage_start, stage_stop);

    int cur_nodes = rows;
    u64* cur = d_a;
    u64* next = d_b;

    while (cur_nodes > 1) {
        const int out_nodes = cur_nodes / 2;
        const int blocks = (out_nodes + threads - 1) / threads;

        HIP_CHECK(hipEventRecord(stage_start));
        merkle_reduce_kernel<<<blocks, threads>>>(cur, next, out_nodes);
        HIP_CHECK(hipGetLastError());
        HIP_CHECK(hipEventRecord(stage_stop));
        HIP_CHECK(hipEventSynchronize(stage_stop));

        const float ms = event_ms(stage_start, stage_stop);
        result.reduce_level_ms.push_back(ms);
        result.reduce_ms += ms;

        std::swap(cur, next);
        cur_nodes = out_nodes;
    }

    HIP_CHECK(hipMemcpy(d_root_out, cur, P2_DIGEST * sizeof(u64), hipMemcpyDeviceToDevice));

    HIP_CHECK(hipEventRecord(total_stop));
    HIP_CHECK(hipEventSynchronize(total_stop));
    result.total_ms = event_ms(total_start, total_stop);

    HIP_CHECK(hipEventDestroy(total_start));
    HIP_CHECK(hipEventDestroy(total_stop));
    HIP_CHECK(hipEventDestroy(stage_start));
    HIP_CHECK(hipEventDestroy(stage_stop));

    HIP_CHECK(hipFree(d_a));
    HIP_CHECK(hipFree(d_b));

    return result;
}

static GpuFriResult gpu_fri_chain_device_resident(
    u64* d_layer0,
    int leaves,
    int cols,
    int final_rows,
    bool copy_final_matrix
) {
    if (!is_power_of_two_u64((u64)leaves)) throw std::runtime_error("FRI leaves must be power of two");
    if (!is_power_of_two_u64((u64)final_rows)) throw std::runtime_error("FRI final_rows must be power of two");
    if (final_rows <= 0 || final_rows > leaves) throw std::runtime_error("bad FRI final_rows");

    GpuFriResult out;
    out.final_rows = final_rows;

    const int rounds = log2_u64((u64)leaves) - log2_u64((u64)final_rows);
    const int root_count = rounds + 1;

    u64* d_next = nullptr;
    u64* d_work = nullptr;
    u64* d_roots = nullptr;
    u64* d_betas = nullptr;

    HIP_CHECK(hipMalloc(&d_work, (size_t)leaves * cols * sizeof(u64)));
    d_next = d_work;
    HIP_CHECK(hipMalloc(&d_roots, (size_t)root_count * P2_DIGEST * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_betas, (size_t)rounds * sizeof(u64)));

    hipEvent_t fold_start, fold_stop, beta_start, beta_stop, copy_start, copy_stop;
    HIP_CHECK(hipEventCreate(&fold_start));
    HIP_CHECK(hipEventCreate(&fold_stop));
    HIP_CHECK(hipEventCreate(&beta_start));
    HIP_CHECK(hipEventCreate(&beta_stop));
    HIP_CHECK(hipEventCreate(&copy_start));
    HIP_CHECK(hipEventCreate(&copy_stop));

    u64* d_cur = d_layer0;
    int rows = leaves;
    int round = 0;

    while (rows > final_rows) {
        GpuRootDeviceResult root = gpu_merkle_root_to_device(
            d_cur,
            rows,
            cols,
            d_roots + (size_t)round * P2_DIGEST
        );

        out.layer_merkle_ms.push_back(root.total_ms);
        out.merkle_ms += root.total_ms;

        HIP_CHECK(hipEventRecord(beta_start));
        fri_beta_kernel<<<1, 1>>>(d_roots, d_betas, round);
        HIP_CHECK(hipGetLastError());
        HIP_CHECK(hipEventRecord(beta_stop));
        HIP_CHECK(hipEventSynchronize(beta_stop));

        const int out_rows = rows / 2;
        const int total_out = out_rows * cols;
        const int threads = 256;
        const int blocks = (total_out + threads - 1) / threads;

        HIP_CHECK(hipEventRecord(fold_start));
        fri_fold_kernel_device_beta<<<blocks, threads>>>(
            d_cur,
            d_next,
            d_betas,
            round,
            out_rows,
            cols
        );
        HIP_CHECK(hipGetLastError());
        HIP_CHECK(hipEventRecord(fold_stop));
        HIP_CHECK(hipEventSynchronize(fold_stop));

        const float fms = event_ms(fold_start, fold_stop);
        out.layer_fold_ms.push_back(fms);
        out.fold_ms += fms;

        std::swap(d_cur, d_next);
        rows = out_rows;
        ++round;
    }

    GpuRootDeviceResult final_root = gpu_merkle_root_to_device(
        d_cur,
        rows,
        cols,
        d_roots + (size_t)round * P2_DIGEST
    );

    out.layer_merkle_ms.push_back(final_root.total_ms);
    out.merkle_ms += final_root.total_ms;

    out.rounds = rounds;
    out.total_ms = out.merkle_ms + out.fold_ms;

    out.roots.assign((size_t)root_count * P2_DIGEST, 0);
    out.betas.assign((size_t)rounds, 0);

    HIP_CHECK(hipEventRecord(copy_start));
    HIP_CHECK(hipMemcpy(out.roots.data(), d_roots, out.roots.size() * sizeof(u64), hipMemcpyDeviceToHost));
    if (rounds > 0) {
        HIP_CHECK(hipMemcpy(out.betas.data(), d_betas, out.betas.size() * sizeof(u64), hipMemcpyDeviceToHost));
    }

    if (copy_final_matrix) {
        out.final_matrix.assign((size_t)final_rows * cols, 0);
        HIP_CHECK(hipMemcpy(out.final_matrix.data(), d_cur, out.final_matrix.size() * sizeof(u64), hipMemcpyDeviceToHost));
    }
    HIP_CHECK(hipEventRecord(copy_stop));
    HIP_CHECK(hipEventSynchronize(copy_stop));

    HIP_CHECK(hipEventDestroy(fold_start));
    HIP_CHECK(hipEventDestroy(fold_stop));
    HIP_CHECK(hipEventDestroy(beta_start));
    HIP_CHECK(hipEventDestroy(beta_stop));
    HIP_CHECK(hipEventDestroy(copy_start));
    HIP_CHECK(hipEventDestroy(copy_stop));

    // d_cur/d_next are swapped during folding.
    // d_next may point back to caller-owned d_layer0 when the number of FRI rounds is odd.
    // Only free the work buffer allocated inside this function.
    HIP_CHECK(hipFree(d_work));
    HIP_CHECK(hipFree(d_roots));
    HIP_CHECK(hipFree(d_betas));

    return out;
}

struct GpuE2EResult {
    GpuNttResult ntt;
    GpuFriResult fri;

    float h2d_ms = 0.0f;
    float gpu_pipeline_ms = 0.0f;
    float e2e_ms = 0.0f;
};

static GpuE2EResult gpu_e2e_ntt_fri(
    const std::vector<u64>& raw_matrix,
    int rows,
    int cols,
    int final_rows,
    bool copy_final_matrix
) {
    GpuE2EResult out;

    u64* d_matrix = nullptr;
    HIP_CHECK(hipMalloc(&d_matrix, raw_matrix.size() * sizeof(u64)));

    hipEvent_t h2d_start, h2d_stop;
    HIP_CHECK(hipEventCreate(&h2d_start));
    HIP_CHECK(hipEventCreate(&h2d_stop));

    HIP_CHECK(hipEventRecord(h2d_start));
    HIP_CHECK(hipMemcpy(d_matrix, raw_matrix.data(), raw_matrix.size() * sizeof(u64), hipMemcpyHostToDevice));
    HIP_CHECK(hipEventRecord(h2d_stop));
    HIP_CHECK(hipEventSynchronize(h2d_stop));
    out.h2d_ms = event_ms(h2d_start, h2d_stop);

    out.ntt = gpu_ntt_fast_inplace(d_matrix, rows, cols);

    out.fri = gpu_fri_chain_device_resident(
        d_matrix,
        rows,
        cols,
        final_rows,
        copy_final_matrix
    );

    out.gpu_pipeline_ms = out.ntt.total_ms + out.fri.total_ms;
    out.e2e_ms = out.h2d_ms + out.gpu_pipeline_ms;

    HIP_CHECK(hipEventDestroy(h2d_start));
    HIP_CHECK(hipEventDestroy(h2d_stop));

    HIP_CHECK(hipFree(d_matrix));

    return out;
}

static void run_e2e_correctness(
    const std::vector<u64>& raw_matrix,
    int rows,
    int cols,
    int final_rows,
    const FrozenPoseidon2& p2,
    const GpuE2EResult& gpu
) {
    std::vector<u64> cpu_matrix = raw_matrix;
    cpu_ntt_columns_inplace(cpu_matrix, rows, cols);

    CpuFriResult cpu = cpu_fri_chain(cpu_matrix, rows, cols, final_rows, p2);

    if (cpu.roots.size() != gpu.fri.roots.size()) {
        throw std::runtime_error("E2E FRI root count mismatch");
    }

    for (size_t i = 0; i < cpu.roots.size(); ++i) {
        if (cpu.roots[i] != gpu.fri.roots[i]) {
            std::ostringstream os;
            os << "E2E root mismatch at element " << i
               << " cpu=" << hex64(cpu.roots[i])
               << " gpu=" << hex64(gpu.fri.roots[i]);
            throw std::runtime_error(os.str());
        }
    }

    if (cpu.betas.size() != gpu.fri.betas.size()) {
        throw std::runtime_error("E2E beta count mismatch");
    }

    for (size_t i = 0; i < cpu.betas.size(); ++i) {
        if (cpu.betas[i] != gpu.fri.betas[i]) {
            std::ostringstream os;
            os << "E2E beta mismatch at round " << i
               << " cpu=" << hex64(cpu.betas[i])
               << " gpu=" << hex64(gpu.fri.betas[i]);
            throw std::runtime_error(os.str());
        }
    }

    if (cpu.final_matrix.size() != gpu.fri.final_matrix.size()) {
        throw std::runtime_error("E2E final matrix size mismatch");
    }

    for (size_t i = 0; i < cpu.final_matrix.size(); ++i) {
        if (cpu.final_matrix[i] != gpu.fri.final_matrix[i]) {
            std::ostringstream os;
            os << "E2E final matrix mismatch at element " << i
               << " cpu=" << hex64(cpu.final_matrix[i])
               << " gpu=" << hex64(gpu.fri.final_matrix[i]);
            throw std::runtime_error(os.str());
        }
    }
}

static void report_e2e(
    const char* title,
    const FrozenPoseidon2& p2,
    const Options& opt,
    const GpuE2EResult& e2e,
    bool correctness_done
) {
    const int root_count = (int)(e2e.fri.roots.size() / P2_DIGEST);
    const u64* final_root = &e2e.fri.roots[(size_t)(root_count - 1) * P2_DIGEST];

    std::cout << title << "\n";
    std::cout << "status: PASS\n";
    std::cout << "operator: qingming-g64-ntt-fast-plus-fri-g64\n";
    std::cout << "field: Goldilocks/G64\n";
    std::cout << "p: " << G64_P << "\n";
    std::cout << "ntt_root_2_32: " << hex64(G64_ROOT_2_32) << "\n";
    std::cout << "hash: QINGMING-POSEIDON2-G64\n";
    std::cout << "merkle_operator: generic-layered-final\n";
    std::cout << "fri_operator: commit-fold-chain\n";
    std::cout << "poseidon2_params_fingerprint: " << hex64(p2.params_fingerprint) << "\n";
    std::cout << "poseidon2_test_vectors_fingerprint: " << hex64(p2.vectors_fingerprint) << "\n";
    std::cout << "layer0_rows: " << opt.leaf_count << "\n";
    std::cout << "committed_columns: " << opt.committed_columns << "\n";
    std::cout << "committed_elements_layer0: " << ((u64)opt.leaf_count * (u64)opt.committed_columns) << "\n";
    std::cout << "final_rows: " << opt.final_rows << "\n";
    std::cout << "fri_rounds: " << e2e.fri.rounds << "\n";
    std::cout << "fri_root_count: " << root_count << "\n";
    std::cout << "data_residency: large_matrix_h2d_once_then_device_resident_until_final_outputs\n";

    std::cout << "h2d_input_ms: " << std::fixed << std::setprecision(3) << e2e.h2d_ms << "\n";
    std::cout << "gpu_ntt_total_ms: " << std::fixed << std::setprecision(3) << e2e.ntt.total_ms << "\n";
    std::cout << "gpu_ntt_bit_reverse_ms: " << std::fixed << std::setprecision(3) << e2e.ntt.bit_reverse_ms << "\n";
    std::cout << "gpu_ntt_stages_ms: " << std::fixed << std::setprecision(3) << e2e.ntt.stages_ms << "\n";
    std::cout << "gpu_fri_total_ms: " << std::fixed << std::setprecision(3) << e2e.fri.total_ms << "\n";
    std::cout << "gpu_fri_merkle_ms: " << std::fixed << std::setprecision(3) << e2e.fri.merkle_ms << "\n";
    std::cout << "gpu_fri_fold_ms: " << std::fixed << std::setprecision(3) << e2e.fri.fold_ms << "\n";
    std::cout << "gpu_pipeline_ms: " << std::fixed << std::setprecision(3) << e2e.gpu_pipeline_ms << "\n";
    std::cout << "e2e_ms: " << std::fixed << std::setprecision(3) << e2e.e2e_ms << "\n";

    std::cout << "fri_roots_fingerprint: " << hex64(fingerprint_values(e2e.fri.roots, "QINGMING-E2E-FRI-ROOTS")) << "\n";
    std::cout << "fri_betas_fingerprint: " << hex64(fingerprint_values(e2e.fri.betas, "QINGMING-E2E-FRI-BETAS")) << "\n";
    if (!e2e.fri.final_matrix.empty()) {
        std::cout << "fri_final_matrix_fingerprint: " << hex64(fingerprint_values(e2e.fri.final_matrix, "QINGMING-E2E-FINAL-MATRIX")) << "\n";
    } else {
        std::cout << "fri_final_matrix_fingerprint: SKIPPED\n";
    }

    std::cout << "cpu_gpu_e2e_roots_compare: " << (correctness_done ? "PASS" : "SKIPPED") << "\n";
    std::cout << "cpu_gpu_e2e_betas_compare: " << (correctness_done ? "PASS" : "SKIPPED") << "\n";
    std::cout << "cpu_gpu_e2e_final_matrix_compare: " << (correctness_done ? "PASS" : "SKIPPED") << "\n";
    print_digest("final_root", final_root);
}

static void report_e2e_sweep_row(
    int scale_k,
    int rows,
    int cols,
    int final_rows,
    const GpuE2EResult& e2e
) {
    const int root_count = (int)(e2e.fri.roots.size() / P2_DIGEST);
    const u64* final_root = &e2e.fri.roots[(size_t)(root_count - 1) * P2_DIGEST];

    std::cout
        << scale_k << ","
        << rows << ","
        << cols << ","
        << ((u64)rows * (u64)cols) << ","
        << final_rows << ","
        << e2e.fri.rounds << ","
        << std::fixed << std::setprecision(3) << e2e.h2d_ms << ","
        << std::fixed << std::setprecision(3) << e2e.ntt.total_ms << ","
        << std::fixed << std::setprecision(3) << e2e.fri.total_ms << ","
        << std::fixed << std::setprecision(3) << e2e.gpu_pipeline_ms << ","
        << std::fixed << std::setprecision(3) << e2e.e2e_ms << ","
        << hex64(final_root[0]) << ";"
        << hex64(final_root[1]) << ";"
        << hex64(final_root[2]) << ";"
        << hex64(final_root[3])
        << "\n";
}





static double now_ms_host_clock() {
    using clock = std::chrono::high_resolution_clock;
    static const auto t0 = clock::now();
    const auto t = clock::now();
    return std::chrono::duration<double, std::milli>(t - t0).count();
}


// -----------------------------
// QINGMING-G64-NTT FAST XYZ adapter
// -----------------------------
//
// This adapter replaces the temporary row-wise NTT for the official SCALE27 C=16 path.
//
// Contract:
//   input:
//     host standard contiguous field elements, size = 2^27
//   prelayout:
//     standard [outer][middle][inner] -> fast [inner][middle][outer]
//   fast pipeline:
//     512-point NTT
//     transpose_y_k0_twiddle
//     512-point NTT
//     transpose_x_k1_twiddle
//     512-point final-axis NTT
//   output:
//     device pointer in standard contiguous order
//
// For non-SCALE27 or cols != 16, the prover keeps the earlier row-wise fallback.

static constexpr u64 QM_NTT_FAST_N = (1ULL << 27);
static constexpr int QM_NTT_AXIS = 512;
static constexpr int QM_NTT_AXIS_BITS = 9;
static constexpr int QM_NTT_AXIS2 = QM_NTT_AXIS * QM_NTT_AXIS;
static constexpr int QM_NTT_FINAL_AXIS = 512;
static constexpr int QM_NTT_FINAL_AXIS_BITS = 9;
static constexpr int QM_NTT_FINAL_PLANE = QM_NTT_AXIS * QM_NTT_FINAL_AXIS;
static constexpr int QM_NTT_TILE = 32;
static constexpr int QM_NTT_TILE_ROWS_PER_BLOCK = 8;
static constexpr int QM_NTT_THREADS = 256;

static unsigned ceil_div_u64_fast(u64 value, u64 divisor) {
    return (unsigned)((value + divisor - 1ULL) / divisor);
}

static std::vector<u64> make_powers_table(u64 root, size_t n) {
    std::vector<u64> out(n);
    u64 w = 1;

    for (size_t i = 0; i < n; ++i) {
        out[i] = w;
        w = g64_mul(w, root);
    }

    return out;
}

__global__ __launch_bounds__(QM_NTT_THREADS)
void qm_ntt512_natural_kernel(
    const u64* __restrict__ input,
    u64* __restrict__ output,
    const u64* __restrict__ twiddles512
) {
    const int tid = (int)threadIdx.x;
    const u64 base = (u64)blockIdx.x * (u64)QM_NTT_AXIS;

    __shared__ u64 values[QM_NTT_AXIS];
    __shared__ u64 twiddles[QM_NTT_AXIS / 2];

    twiddles[tid] = twiddles512[tid];

    values[tid] = input[base + (u64)tid];
    values[tid + QM_NTT_AXIS / 2] = input[base + (u64)(tid + QM_NTT_AXIS / 2)];
    __syncthreads();

    #pragma unroll
    for (int len = QM_NTT_AXIS / 2; len > 0; len >>= 1) {
        const int offset = tid % len;
        const int butterfly_group = tid / len;
        const int left = butterfly_group * len * 2 + offset;
        const int right = left + len;

        const u64 a = values[left];
        const u64 b = values[right];
        const u64 w = twiddles[offset * ((QM_NTT_AXIS / 2) / len)];

        values[left] = g64_add(a, b);
        values[right] = g64_mul(g64_sub(a, b), w);
        __syncthreads();
    }

    const int k0 = tid;
    const int k1 = tid + QM_NTT_AXIS / 2;

    const int rev0 = (int)(__brev((unsigned)k0) >> (32 - QM_NTT_AXIS_BITS));
    const int rev1 = (int)(__brev((unsigned)k1) >> (32 - QM_NTT_AXIS_BITS));

    output[base + (u64)k0] = values[rev0];
    output[base + (u64)k1] = values[rev1];
}

__global__ __launch_bounds__(QM_NTT_THREADS)
void qm_ntt_final_axis_natural_kernel(
    const u64* __restrict__ input,
    u64* __restrict__ output,
    const u64* __restrict__ twiddles_final
) {
    const int tid = (int)threadIdx.x;
    constexpr int axis = QM_NTT_FINAL_AXIS;
    constexpr int half_axis = axis / 2;

    __shared__ u64 values[QM_NTT_AXIS];
    __shared__ u64 twiddles[QM_NTT_AXIS / 2];

    if (tid < half_axis) {
        const u64 base = (u64)blockIdx.x * (u64)QM_NTT_FINAL_AXIS;
        twiddles[tid] = twiddles_final[tid];
        values[tid] = input[base + (u64)tid];
        values[tid + half_axis] = input[base + (u64)(tid + half_axis)];
    }
    __syncthreads();

    #pragma unroll
    for (int len = half_axis; len > 0; len >>= 1) {
        if (tid < half_axis) {
            const int offset = tid % len;
            const int butterfly_group = tid / len;
            const int left = butterfly_group * len * 2 + offset;
            const int right = left + len;

            const u64 a = values[left];
            const u64 b = values[right];
            const u64 w = twiddles[offset * (half_axis / len)];

            values[left] = g64_add(a, b);
            values[right] = g64_mul(g64_sub(a, b), w);
        }
        __syncthreads();
    }

    if (tid < half_axis) {
        const u64 base = (u64)blockIdx.x * (u64)QM_NTT_FINAL_AXIS;
        const int k0 = tid;
        const int k1 = tid + half_axis;

        const int rev0 = (int)(__brev((unsigned)k0) >> (32 - QM_NTT_FINAL_AXIS_BITS));
        const int rev1 = (int)(__brev((unsigned)k1) >> (32 - QM_NTT_FINAL_AXIS_BITS));

        output[base + (u64)k0] = values[rev0];
        output[base + (u64)k1] = values[rev1];
    }
}

__global__ __launch_bounds__(QM_NTT_TILE * QM_NTT_TILE_ROWS_PER_BLOCK)
void qm_transpose_y_k0_twiddle_kernel(
    const u64* __restrict__ input,
    u64* __restrict__ output,
    const u64* __restrict__ twiddle_stride_low
) {
    __shared__ u64 tile[QM_NTT_TILE][QM_NTT_TILE + 1];

    const int tx = (int)threadIdx.x;
    const int ty = (int)threadIdx.y;
    const int x = (int)blockIdx.z;

    #pragma unroll
    for (int j = 0; j < QM_NTT_TILE; j += QM_NTT_TILE_ROWS_PER_BLOCK) {
        const int y = (int)blockIdx.y * QM_NTT_TILE + ty + j;
        const int k0 = (int)blockIdx.x * QM_NTT_TILE + tx;

        const u64 input_position =
            (u64)x * (u64)QM_NTT_AXIS2 +
            (u64)y * (u64)QM_NTT_AXIS +
            (u64)k0;

        const u64 twiddle_position =
            (u64)y * (u64)QM_NTT_AXIS + (u64)k0;

        tile[ty + j][tx] =
            g64_mul(input[input_position], twiddle_stride_low[twiddle_position]);
    }
    __syncthreads();

    #pragma unroll
    for (int j = 0; j < QM_NTT_TILE; j += QM_NTT_TILE_ROWS_PER_BLOCK) {
        const int k0_out = (int)blockIdx.x * QM_NTT_TILE + ty + j;
        const int y_out = (int)blockIdx.y * QM_NTT_TILE + tx;

        const u64 output_position =
            (u64)x * (u64)QM_NTT_AXIS2 +
            (u64)k0_out * (u64)QM_NTT_AXIS +
            (u64)y_out;

        output[output_position] = tile[tx][ty + j];
    }
}

__global__ __launch_bounds__(QM_NTT_TILE * QM_NTT_TILE_ROWS_PER_BLOCK)
void qm_transpose_x_k1_twiddle_kernel(
    const u64* __restrict__ input,
    u64* __restrict__ output,
    const u64* __restrict__ twiddle_plain,
    const u64* __restrict__ twiddle_stride_low
) {
    __shared__ u64 tile[QM_NTT_TILE][QM_NTT_TILE + 1];

    const int tx = (int)threadIdx.x;
    const int ty = (int)threadIdx.y;
    const int k0 = (int)blockIdx.z;

    #pragma unroll
    for (int j = 0; j < QM_NTT_TILE; j += QM_NTT_TILE_ROWS_PER_BLOCK) {
        const int x = (int)blockIdx.y * QM_NTT_TILE + ty + j;
        const int k1 = (int)blockIdx.x * QM_NTT_TILE + tx;

        u64 value = 0;
        if (x < QM_NTT_FINAL_AXIS && k1 < QM_NTT_AXIS) {
            const u64 input_position =
                (u64)x * (u64)QM_NTT_AXIS2 +
                (u64)k0 * (u64)QM_NTT_AXIS +
                (u64)k1;

            const u64 plain_position =
                (u64)x * (u64)QM_NTT_AXIS + (u64)k0;
            const u64 stride_low_position =
                (u64)x * (u64)QM_NTT_AXIS + (u64)k1;

            value = g64_mul(input[input_position], twiddle_plain[plain_position]);
            value = g64_mul(value, twiddle_stride_low[stride_low_position]);
        }

        tile[ty + j][tx] = value;
    }
    __syncthreads();

    #pragma unroll
    for (int j = 0; j < QM_NTT_TILE; j += QM_NTT_TILE_ROWS_PER_BLOCK) {
        const int k1_out = (int)blockIdx.x * QM_NTT_TILE + ty + j;
        const int x_out = (int)blockIdx.y * QM_NTT_TILE + tx;

        if (k1_out < QM_NTT_AXIS && x_out < QM_NTT_FINAL_AXIS) {
            const u64 output_position =
                (u64)k0 * (u64)QM_NTT_FINAL_PLANE +
                (u64)k1_out * (u64)QM_NTT_FINAL_AXIS +
                (u64)x_out;

            output[output_position] = tile[tx][ty + j];
        }
    }
}

__global__ __launch_bounds__(QM_NTT_TILE * QM_NTT_TILE_ROWS_PER_BLOCK)
void qm_prelayout_tiled_kernel(
    const u64* __restrict__ input,
    u64* __restrict__ output
) {
    __shared__ u64 tile[QM_NTT_TILE][QM_NTT_TILE + 1];

    const int tx = (int)threadIdx.x;
    const int ty = (int)threadIdx.y;
    const int middle = (int)blockIdx.z;

    #pragma unroll
    for (int j = 0; j < QM_NTT_TILE; j += QM_NTT_TILE_ROWS_PER_BLOCK) {
        const int outer = (int)blockIdx.y * QM_NTT_TILE + ty + j;
        const int inner = (int)blockIdx.x * QM_NTT_TILE + tx;

        u64 value = 0;
        if (outer < QM_NTT_AXIS && inner < QM_NTT_FINAL_AXIS) {
            const u64 input_position =
                (u64)outer * (u64)QM_NTT_FINAL_PLANE +
                (u64)middle * (u64)QM_NTT_FINAL_AXIS +
                (u64)inner;

            value = input[input_position];
        }

        tile[ty + j][tx] = value;
    }
    __syncthreads();

    #pragma unroll
    for (int j = 0; j < QM_NTT_TILE; j += QM_NTT_TILE_ROWS_PER_BLOCK) {
        const int inner_out = (int)blockIdx.x * QM_NTT_TILE + ty + j;
        const int outer_out = (int)blockIdx.y * QM_NTT_TILE + tx;

        if (inner_out < QM_NTT_FINAL_AXIS && outer_out < QM_NTT_AXIS) {
            const u64 output_position =
                (u64)inner_out * (u64)QM_NTT_AXIS2 +
                (u64)middle * (u64)QM_NTT_AXIS +
                (u64)outer_out;

            output[output_position] = tile[tx][ty + j];
        }
    }
}

struct PreparedNttLayer {
    u64* d_layer0 = nullptr;
    u64* d_layer0_saved = nullptr;

    GpuNttResult ntt;

    float h2d_ms = 0.0f;
    float snapshot_ms = 0.0f;

    float fast_prelayout_ms = 0.0f;
    float fast_core_ms = 0.0f;
    float fast_total_ms = 0.0f;

    bool used_fast_xyz = false;
};

static void build_fast_xyz_twiddle_tables(
    std::vector<u64>& twiddles512,
    std::vector<u64>& twiddles_final,
    std::vector<u64>& twiddle_plain,
    std::vector<u64>& twiddle_stride_low
) {
    const u64 omega_n = g64_pow_u64(G64_ROOT_2_32, (1ULL << 32) / QM_NTT_FAST_N);
    const u64 omega_axis = g64_pow_u64(omega_n, QM_NTT_FAST_N / QM_NTT_AXIS);
    const u64 omega_final = g64_pow_u64(omega_n, QM_NTT_FAST_N / QM_NTT_FINAL_AXIS);

    twiddles512 = make_powers_table(omega_axis, QM_NTT_AXIS / 2);
    twiddles_final = make_powers_table(omega_final, QM_NTT_AXIS / 2);

    twiddle_plain.assign((size_t)QM_NTT_AXIS2, 0);
    twiddle_stride_low.assign((size_t)QM_NTT_AXIS2, 0);

    for (int a = 0; a < QM_NTT_AXIS; ++a) {
        for (int b = 0; b < QM_NTT_AXIS; ++b) {
            twiddle_plain[(size_t)a * QM_NTT_AXIS + b] =
                g64_pow_u64(omega_n, (u64)a * (u64)b);

            twiddle_stride_low[(size_t)a * QM_NTT_AXIS + b] =
                g64_pow_u64(omega_n, (u64)QM_NTT_FINAL_AXIS * (u64)a * (u64)b);
        }
    }
}

static PreparedNttLayer prepare_layer0_rowwise_fallback(
    const std::vector<u64>& raw_matrix,
    int rows,
    int cols
) {
    PreparedNttLayer out;
    out.used_fast_xyz = false;

    HIP_CHECK(hipMalloc(&out.d_layer0, raw_matrix.size() * sizeof(u64)));

    hipEvent_t h2d_start, h2d_stop, snap_start, snap_stop;
    HIP_CHECK(hipEventCreate(&h2d_start));
    HIP_CHECK(hipEventCreate(&h2d_stop));
    HIP_CHECK(hipEventCreate(&snap_start));
    HIP_CHECK(hipEventCreate(&snap_stop));

    HIP_CHECK(hipEventRecord(h2d_start));
    HIP_CHECK(hipMemcpy(out.d_layer0, raw_matrix.data(), raw_matrix.size() * sizeof(u64), hipMemcpyHostToDevice));
    HIP_CHECK(hipEventRecord(h2d_stop));
    HIP_CHECK(hipEventSynchronize(h2d_stop));
    out.h2d_ms = event_ms(h2d_start, h2d_stop);

    out.ntt = gpu_ntt_fast_inplace(out.d_layer0, rows, cols);

    HIP_CHECK(hipMalloc(&out.d_layer0_saved, raw_matrix.size() * sizeof(u64)));

    HIP_CHECK(hipEventRecord(snap_start));
    HIP_CHECK(hipMemcpy(out.d_layer0_saved, out.d_layer0, raw_matrix.size() * sizeof(u64), hipMemcpyDeviceToDevice));
    HIP_CHECK(hipEventRecord(snap_stop));
    HIP_CHECK(hipEventSynchronize(snap_stop));
    out.snapshot_ms = event_ms(snap_start, snap_stop);

    HIP_CHECK(hipEventDestroy(h2d_start));
    HIP_CHECK(hipEventDestroy(h2d_stop));
    HIP_CHECK(hipEventDestroy(snap_start));
    HIP_CHECK(hipEventDestroy(snap_stop));

    return out;
}

static PreparedNttLayer prepare_layer0_fast_xyz(
    const std::vector<u64>& raw_matrix,
    int rows,
    int cols
) {
    const u64 scale_elements = (u64)rows * (u64)cols;

    if (scale_elements != QM_NTT_FAST_N || cols != 16) {
        return prepare_layer0_rowwise_fallback(raw_matrix, rows, cols);
    }

    PreparedNttLayer out;
    out.used_fast_xyz = true;

    u64* d_fast = nullptr;
    u64* d_twiddles512 = nullptr;
    u64* d_twiddles_final = nullptr;
    u64* d_twiddle_plain = nullptr;
    u64* d_twiddle_stride_low = nullptr;

    std::vector<u64> twiddles512;
    std::vector<u64> twiddles_final;
    std::vector<u64> twiddle_plain;
    std::vector<u64> twiddle_stride_low;
    build_fast_xyz_twiddle_tables(
        twiddles512,
        twiddles_final,
        twiddle_plain,
        twiddle_stride_low
    );

    HIP_CHECK(hipMalloc(&out.d_layer0, raw_matrix.size() * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_fast, raw_matrix.size() * sizeof(u64)));
    HIP_CHECK(hipMalloc(&out.d_layer0_saved, raw_matrix.size() * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_twiddles512, twiddles512.size() * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_twiddles_final, twiddles_final.size() * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_twiddle_plain, twiddle_plain.size() * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_twiddle_stride_low, twiddle_stride_low.size() * sizeof(u64)));

    hipEvent_t h2d_start, h2d_stop, pre_start, pre_stop, core_start, core_stop, snap_start, snap_stop;
    HIP_CHECK(hipEventCreate(&h2d_start));
    HIP_CHECK(hipEventCreate(&h2d_stop));
    HIP_CHECK(hipEventCreate(&pre_start));
    HIP_CHECK(hipEventCreate(&pre_stop));
    HIP_CHECK(hipEventCreate(&core_start));
    HIP_CHECK(hipEventCreate(&core_stop));
    HIP_CHECK(hipEventCreate(&snap_start));
    HIP_CHECK(hipEventCreate(&snap_stop));

    HIP_CHECK(hipEventRecord(h2d_start));
    HIP_CHECK(hipMemcpy(out.d_layer0, raw_matrix.data(), raw_matrix.size() * sizeof(u64), hipMemcpyHostToDevice));
    HIP_CHECK(hipMemcpy(d_twiddles512, twiddles512.data(), twiddles512.size() * sizeof(u64), hipMemcpyHostToDevice));
    HIP_CHECK(hipMemcpy(d_twiddles_final, twiddles_final.data(), twiddles_final.size() * sizeof(u64), hipMemcpyHostToDevice));
    HIP_CHECK(hipMemcpy(d_twiddle_plain, twiddle_plain.data(), twiddle_plain.size() * sizeof(u64), hipMemcpyHostToDevice));
    HIP_CHECK(hipMemcpy(d_twiddle_stride_low, twiddle_stride_low.data(), twiddle_stride_low.size() * sizeof(u64), hipMemcpyHostToDevice));
    HIP_CHECK(hipEventRecord(h2d_stop));
    HIP_CHECK(hipEventSynchronize(h2d_stop));
    out.h2d_ms = event_ms(h2d_start, h2d_stop);

    const dim3 pre_threads(QM_NTT_TILE, QM_NTT_TILE_ROWS_PER_BLOCK, 1);
    const dim3 pre_blocks(
        ceil_div_u64_fast(QM_NTT_FINAL_AXIS, QM_NTT_TILE),
        QM_NTT_AXIS / QM_NTT_TILE,
        QM_NTT_AXIS
    );

    HIP_CHECK(hipEventRecord(pre_start));
    qm_prelayout_tiled_kernel<<<pre_blocks, pre_threads>>>(
        out.d_layer0,
        d_fast
    );
    HIP_CHECK(hipGetLastError());
    HIP_CHECK(hipEventRecord(pre_stop));
    HIP_CHECK(hipEventSynchronize(pre_stop));
    out.fast_prelayout_ms = event_ms(pre_start, pre_stop);

    const dim3 ntt_threads(QM_NTT_THREADS);
    const dim3 ntt512_blocks((unsigned)(QM_NTT_FAST_N / QM_NTT_AXIS));
    const dim3 final_ntt_blocks((unsigned)(QM_NTT_FAST_N / QM_NTT_FINAL_AXIS));
    const dim3 transpose_threads(QM_NTT_TILE, QM_NTT_TILE_ROWS_PER_BLOCK, 1);
    const dim3 transpose_y_blocks(
        QM_NTT_AXIS / QM_NTT_TILE,
        QM_NTT_AXIS / QM_NTT_TILE,
        QM_NTT_FINAL_AXIS
    );
    const dim3 transpose_x_blocks(
        QM_NTT_AXIS / QM_NTT_TILE,
        ceil_div_u64_fast(QM_NTT_FINAL_AXIS, QM_NTT_TILE),
        QM_NTT_AXIS
    );

    HIP_CHECK(hipEventRecord(core_start));

    qm_ntt512_natural_kernel<<<ntt512_blocks, ntt_threads>>>(
        d_fast,
        out.d_layer0,
        d_twiddles512
    );

    qm_transpose_y_k0_twiddle_kernel<<<transpose_y_blocks, transpose_threads>>>(
        out.d_layer0,
        d_fast,
        d_twiddle_stride_low
    );

    qm_ntt512_natural_kernel<<<ntt512_blocks, ntt_threads>>>(
        d_fast,
        out.d_layer0,
        d_twiddles512
    );

    qm_transpose_x_k1_twiddle_kernel<<<transpose_x_blocks, transpose_threads>>>(
        out.d_layer0,
        d_fast,
        d_twiddle_plain,
        d_twiddle_stride_low
    );

    qm_ntt512_natural_kernel<<<ntt512_blocks, ntt_threads>>>(
        d_fast,
        out.d_layer0,
        d_twiddles512
    );

    HIP_CHECK(hipGetLastError());
    HIP_CHECK(hipEventRecord(core_stop));
    HIP_CHECK(hipEventSynchronize(core_stop));
    out.fast_core_ms = event_ms(core_start, core_stop);

    HIP_CHECK(hipEventRecord(snap_start));
    HIP_CHECK(hipMemcpy(out.d_layer0_saved, out.d_layer0, raw_matrix.size() * sizeof(u64), hipMemcpyDeviceToDevice));
    HIP_CHECK(hipEventRecord(snap_stop));
    HIP_CHECK(hipEventSynchronize(snap_stop));
    out.snapshot_ms = event_ms(snap_start, snap_stop);

    out.fast_total_ms = out.fast_prelayout_ms + out.fast_core_ms;
    out.ntt.total_ms = out.fast_total_ms;
    out.ntt.bit_reverse_ms = 0.0f;
    out.ntt.stages_ms = out.fast_core_ms;

    HIP_CHECK(hipEventDestroy(h2d_start));
    HIP_CHECK(hipEventDestroy(h2d_stop));
    HIP_CHECK(hipEventDestroy(pre_start));
    HIP_CHECK(hipEventDestroy(pre_stop));
    HIP_CHECK(hipEventDestroy(core_start));
    HIP_CHECK(hipEventDestroy(core_stop));
    HIP_CHECK(hipEventDestroy(snap_start));
    HIP_CHECK(hipEventDestroy(snap_stop));

    HIP_CHECK(hipFree(d_twiddles512));
    HIP_CHECK(hipFree(d_twiddles_final));
    HIP_CHECK(hipFree(d_twiddle_plain));
    HIP_CHECK(hipFree(d_twiddle_stride_low));
    HIP_CHECK(hipFree(d_fast));

    return out;
}


// -----------------------------
// QINGMING-PROOF-G64 v1 builder
// -----------------------------

static constexpr int QMP_G64_V1_QUERY_COUNT = 32;

struct QmpHeader {
    u64 version = 1;
    u64 poseidon2_params_fingerprint = 0;
    u64 poseidon2_test_vectors_fingerprint = 0;
    u64 ntt_root_2_32 = G64_ROOT_2_32;
    u64 scale_log2 = 0;
    u64 committed_columns = 0;
    u64 layer0_rows = 0;
    u64 final_rows = 1;
    u64 fri_rounds = 0;
    u64 fri_root_count = 0;
    u64 fri_query_count = QMP_G64_V1_QUERY_COUNT;
};

static int log2_exact_u64(u64 x, const char* what) {
    if (!is_power_of_two_u64(x)) {
        throw std::runtime_error(std::string(what) + " must be power of two");
    }
    return log2_u64(x);
}

static std::vector<u64> transcript_query_indices(
    const std::vector<u64>& roots,
    const std::vector<u64>& final_values,
    int query_count,
    int layer0_rows,
    const FrozenPoseidon2& p2
) {
    std::vector<u64> indices;
    indices.reserve(query_count);

    if (!is_power_of_two_u64((u64)layer0_rows)) {
        throw std::runtime_error("layer0_rows must be power of two for query sampling");
    }

    for (int q = 0; q < query_count; ++q) {
        std::vector<u64> input;
        input.reserve(roots.size() + final_values.size() + 1);

        for (u64 x : roots) input.push_back(x);
        for (u64 x : final_values) input.push_back(x);
        input.push_back((u64)q);

        u64 digest[P2_DIGEST];
        cpu_hash_elements(input, DOMAIN_TRANSCRIPT, p2, digest);

        indices.push_back(digest[0] & ((u64)layer0_rows - 1));
    }

    return indices;
}

static void write_u64_le(std::ostream& out, u64 x) {
    for (int i = 0; i < 8; ++i) {
        char b = (char)((x >> (8 * i)) & 0xff);
        out.write(&b, 1);
    }
}

static void write_u64_vec_le(std::ostream& out, const std::vector<u64>& xs) {
    for (u64 x : xs) write_u64_le(out, x);
}

__global__ void extract_pair_values_kernel(
    const u64* __restrict__ layer,
    const u64* __restrict__ query_indices,
    u64* __restrict__ out_pair_values,
    int round,
    int query_count,
    int cols
) {
    const int idx = blockIdx.x * blockDim.x + threadIdx.x;
    const int total = query_count * 2 * cols;
    if (idx >= total) return;

    const int c = idx % cols;
    const int t = idx / cols;
    const int which = t & 1;
    const int q = t >> 1;

    const u64 idx_r = query_indices[q] >> round;
    const u64 pair_index = idx_r >> 1;
    const u64 row = pair_index * 2 + (u64)which;

    out_pair_values[(size_t)q * 2 * cols + (size_t)which * cols + c] =
        layer[(size_t)row * cols + c];
}

__global__ void extract_pair_paths_kernel(
    const u64* __restrict__ tree,
    const u64* __restrict__ query_indices,
    u64* __restrict__ out_paths,
    int rows,
    int round,
    int query_count
) {
    const int height = 0; // unused placeholder to keep code branchless below
    (void)height;

    const int h = 0;
    (void)h;

    const int tree_height = 0;
    (void)tree_height;

    const int computed_height = __ffs(rows) - 1; // rows is power of two, but __ffs gives bit position.
    (void)computed_height;

    // Use loop-free flattened mapping with host-provided path_len.
}

__global__ void extract_pair_paths_kernel_v2(
    const u64* __restrict__ tree,
    const u64* __restrict__ query_indices,
    u64* __restrict__ out_paths,
    int rows,
    int round,
    int query_count,
    int path_len
) {
    const int idx = blockIdx.x * blockDim.x + threadIdx.x;
    const int total = query_count * path_len * P2_DIGEST;
    if (idx >= total) return;

    const int d = idx % P2_DIGEST;
    const int t = idx / P2_DIGEST;
    const int level_minus_1 = t % path_len;
    const int q = t / path_len;

    const u64 idx_r = query_indices[q] >> round;
    const u64 pair_index = idx_r >> 1;

    const int layer = 1 + level_minus_1;
    const u64 parent_idx = pair_index >> level_minus_1;
    const u64 sibling_idx = parent_idx ^ 1ULL;

    const u64 layer_offset = (u64)2 * (u64)rows - ((u64)rows >> (layer - 1));

    out_paths[(size_t)q * path_len * P2_DIGEST + (size_t)level_minus_1 * P2_DIGEST + d] =
        tree[(size_t)(layer_offset + sibling_idx) * P2_DIGEST + d];
}

struct DeviceTreeForProof {
    u64* d_tree = nullptr;
    int total_nodes = 0;
    float total_ms = 0.0f;
    u64 root[P2_DIGEST] = {0, 0, 0, 0};
};

static void free_device_tree(DeviceTreeForProof& tree) {
    if (tree.d_tree) {
        HIP_CHECK(hipFree(tree.d_tree));
        tree.d_tree = nullptr;
    }
    tree.total_nodes = 0;
    tree.total_ms = 0.0f;
}

static DeviceTreeForProof gpu_build_full_tree_device_for_proof(
    const u64* d_matrix,
    int rows,
    int cols
) {
    DeviceTreeForProof out;
    out.total_nodes = 2 * rows - 1;

    HIP_CHECK(hipMalloc(&out.d_tree, (size_t)out.total_nodes * P2_DIGEST * sizeof(u64)));

    hipEvent_t total_start, total_stop;
    HIP_CHECK(hipEventCreate(&total_start));
    HIP_CHECK(hipEventCreate(&total_stop));

    const int threads = 256;
    const int leaf_blocks = (rows + threads - 1) / threads;

    HIP_CHECK(hipEventRecord(total_start));

    merkle_leaf_kernel<<<leaf_blocks, threads>>>(d_matrix, out.d_tree, rows, cols);
    HIP_CHECK(hipGetLastError());

    int cur_nodes = rows;
    u64* cur_layer = out.d_tree;
    u64* next_layer = out.d_tree + (size_t)rows * P2_DIGEST;

    while (cur_nodes > 1) {
        const int out_nodes = cur_nodes / 2;
        const int blocks = (out_nodes + threads - 1) / threads;

        merkle_reduce_kernel<<<blocks, threads>>>(cur_layer, next_layer, out_nodes);
        HIP_CHECK(hipGetLastError());

        cur_layer = next_layer;
        next_layer += (size_t)out_nodes * P2_DIGEST;
        cur_nodes = out_nodes;
    }

    HIP_CHECK(hipMemcpy(out.root, cur_layer, P2_DIGEST * sizeof(u64), hipMemcpyDeviceToHost));

    HIP_CHECK(hipEventRecord(total_stop));
    HIP_CHECK(hipEventSynchronize(total_stop));
    out.total_ms = event_ms(total_start, total_stop);

    HIP_CHECK(hipEventDestroy(total_start));
    HIP_CHECK(hipEventDestroy(total_stop));

    return out;
}

struct GpuFriRetainedResult : public GpuFriResult {
    std::vector<DeviceTreeForProof> retained_trees;
};

static void free_retained_fri_trees(GpuFriRetainedResult& fri) {
    for (DeviceTreeForProof& tree : fri.retained_trees) {
        free_device_tree(tree);
    }
    fri.retained_trees.clear();
}

static GpuFriRetainedResult gpu_fri_chain_device_resident_retained(
    u64* d_layer0,
    int leaves,
    int cols,
    int final_rows,
    bool copy_final_matrix
) {
    if (!is_power_of_two_u64((u64)leaves)) throw std::runtime_error("FRI leaves must be power of two");
    if (!is_power_of_two_u64((u64)final_rows)) throw std::runtime_error("FRI final_rows must be power of two");
    if (final_rows <= 0 || final_rows > leaves) throw std::runtime_error("bad FRI final_rows");

    GpuFriRetainedResult out;
    out.final_rows = final_rows;

    const int rounds = log2_u64((u64)leaves) - log2_u64((u64)final_rows);
    const int root_count = rounds + 1;

    out.retained_trees.reserve((size_t)root_count);

    u64* d_next = nullptr;
    u64* d_work = nullptr;
    u64* d_roots = nullptr;
    u64* d_betas = nullptr;

    HIP_CHECK(hipMalloc(&d_work, (size_t)leaves * cols * sizeof(u64)));
    d_next = d_work;
    HIP_CHECK(hipMalloc(&d_roots, (size_t)root_count * P2_DIGEST * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_betas, (size_t)rounds * sizeof(u64)));

    hipEvent_t fold_start, fold_stop, beta_start, beta_stop, copy_start, copy_stop;
    HIP_CHECK(hipEventCreate(&fold_start));
    HIP_CHECK(hipEventCreate(&fold_stop));
    HIP_CHECK(hipEventCreate(&beta_start));
    HIP_CHECK(hipEventCreate(&beta_stop));
    HIP_CHECK(hipEventCreate(&copy_start));
    HIP_CHECK(hipEventCreate(&copy_stop));

    u64* d_cur = d_layer0;
    int rows = leaves;
    int round = 0;

    while (rows > final_rows) {
        DeviceTreeForProof tree = gpu_build_full_tree_device_for_proof(d_cur, rows, cols);

        HIP_CHECK(hipMemcpy(
            d_roots + (size_t)round * P2_DIGEST,
            tree.d_tree + (size_t)(tree.total_nodes - 1) * P2_DIGEST,
            P2_DIGEST * sizeof(u64),
            hipMemcpyDeviceToDevice
        ));

        out.layer_merkle_ms.push_back(tree.total_ms);
        out.merkle_ms += tree.total_ms;
        out.retained_trees.push_back(tree);

        HIP_CHECK(hipEventRecord(beta_start));
        fri_beta_kernel<<<1, 1>>>(d_roots, d_betas, round);
        HIP_CHECK(hipGetLastError());
        HIP_CHECK(hipEventRecord(beta_stop));
        HIP_CHECK(hipEventSynchronize(beta_stop));

        const int out_rows = rows / 2;
        const int total_out = out_rows * cols;
        const int threads = 256;
        const int blocks = (total_out + threads - 1) / threads;

        HIP_CHECK(hipEventRecord(fold_start));
        fri_fold_kernel_device_beta<<<blocks, threads>>>(
            d_cur,
            d_next,
            d_betas,
            round,
            out_rows,
            cols
        );
        HIP_CHECK(hipGetLastError());
        HIP_CHECK(hipEventRecord(fold_stop));
        HIP_CHECK(hipEventSynchronize(fold_stop));

        const float fms = event_ms(fold_start, fold_stop);
        out.layer_fold_ms.push_back(fms);
        out.fold_ms += fms;

        std::swap(d_cur, d_next);
        rows = out_rows;
        ++round;
    }

    DeviceTreeForProof final_tree = gpu_build_full_tree_device_for_proof(d_cur, rows, cols);

    HIP_CHECK(hipMemcpy(
        d_roots + (size_t)round * P2_DIGEST,
        final_tree.d_tree + (size_t)(final_tree.total_nodes - 1) * P2_DIGEST,
        P2_DIGEST * sizeof(u64),
        hipMemcpyDeviceToDevice
    ));

    out.layer_merkle_ms.push_back(final_tree.total_ms);
    out.merkle_ms += final_tree.total_ms;
    out.retained_trees.push_back(final_tree);

    out.rounds = rounds;
    out.total_ms = out.merkle_ms + out.fold_ms;

    out.roots.assign((size_t)root_count * P2_DIGEST, 0);
    out.betas.assign((size_t)rounds, 0);

    HIP_CHECK(hipEventRecord(copy_start));
    HIP_CHECK(hipMemcpy(out.roots.data(), d_roots, out.roots.size() * sizeof(u64), hipMemcpyDeviceToHost));
    if (rounds > 0) {
        HIP_CHECK(hipMemcpy(out.betas.data(), d_betas, out.betas.size() * sizeof(u64), hipMemcpyDeviceToHost));
    }

    if (copy_final_matrix) {
        out.final_matrix.assign((size_t)final_rows * cols, 0);
        HIP_CHECK(hipMemcpy(out.final_matrix.data(), d_cur, out.final_matrix.size() * sizeof(u64), hipMemcpyDeviceToHost));
    }
    HIP_CHECK(hipEventRecord(copy_stop));
    HIP_CHECK(hipEventSynchronize(copy_stop));

    HIP_CHECK(hipEventDestroy(fold_start));
    HIP_CHECK(hipEventDestroy(fold_stop));
    HIP_CHECK(hipEventDestroy(beta_start));
    HIP_CHECK(hipEventDestroy(beta_stop));
    HIP_CHECK(hipEventDestroy(copy_start));
    HIP_CHECK(hipEventDestroy(copy_stop));

    HIP_CHECK(hipFree(d_work));
    HIP_CHECK(hipFree(d_roots));
    HIP_CHECK(hipFree(d_betas));

    return out;
}

static void append_openings_for_layer_retained(
    std::vector<u64>& proof_openings,
    const u64* d_layer,
    const DeviceTreeForProof& tree,
    int rows,
    int cols,
    int round,
    const std::vector<u64>& query_indices
) {
    const int query_count = (int)query_indices.size();
    const int height = log2_u64((u64)rows);
    const int path_len = height - 1;

    u64* d_query_indices = nullptr;
    u64* d_pairs = nullptr;
    u64* d_paths = nullptr;

    const size_t pair_count = (size_t)query_count * 2 * cols;
    const size_t path_count = (size_t)query_count * path_len * P2_DIGEST;

    HIP_CHECK(hipMalloc(&d_query_indices, query_indices.size() * sizeof(u64)));
    HIP_CHECK(hipMemcpy(d_query_indices, query_indices.data(), query_indices.size() * sizeof(u64), hipMemcpyHostToDevice));

    HIP_CHECK(hipMalloc(&d_pairs, pair_count * sizeof(u64)));
    if (path_count > 0) {
        HIP_CHECK(hipMalloc(&d_paths, path_count * sizeof(u64)));
    }

    const int threads = 256;

    const int pair_blocks = (int)((pair_count + threads - 1) / threads);
    extract_pair_values_kernel<<<pair_blocks, threads>>>(
        d_layer,
        d_query_indices,
        d_pairs,
        round,
        query_count,
        cols
    );
    HIP_CHECK(hipGetLastError());

    if (path_count > 0) {
        const int path_blocks = (int)((path_count + threads - 1) / threads);
        extract_pair_paths_kernel_v2<<<path_blocks, threads>>>(
            tree.d_tree,
            d_query_indices,
            d_paths,
            rows,
            round,
            query_count,
            path_len
        );
        HIP_CHECK(hipGetLastError());
    }

    std::vector<u64> h_pairs(pair_count);
    std::vector<u64> h_paths(path_count);

    HIP_CHECK(hipMemcpy(h_pairs.data(), d_pairs, pair_count * sizeof(u64), hipMemcpyDeviceToHost));
    if (path_count > 0) {
        HIP_CHECK(hipMemcpy(h_paths.data(), d_paths, path_count * sizeof(u64), hipMemcpyDeviceToHost));
    }

    for (int q = 0; q < query_count; ++q) {
        for (int i = 0; i < 2 * cols; ++i) {
            proof_openings.push_back(h_pairs[(size_t)q * 2 * cols + i]);
        }

        for (int i = 0; i < path_len * P2_DIGEST; ++i) {
            proof_openings.push_back(h_paths[(size_t)q * path_len * P2_DIGEST + i]);
        }
    }

    HIP_CHECK(hipFree(d_query_indices));
    HIP_CHECK(hipFree(d_pairs));
    if (d_paths) HIP_CHECK(hipFree(d_paths));
}

static void append_openings_for_layer(
    std::vector<u64>& proof_openings,
    const u64* d_layer,
    int rows,
    int cols,
    int round,
    const std::vector<u64>& query_indices
) {
    const int query_count = (int)query_indices.size();
    const int height = log2_u64((u64)rows);
    const int path_len = height - 1;

    DeviceTreeForProof tree = gpu_build_full_tree_device_for_proof(d_layer, rows, cols);

    u64* d_query_indices = nullptr;
    u64* d_pairs = nullptr;
    u64* d_paths = nullptr;

    const size_t pair_count = (size_t)query_count * 2 * cols;
    const size_t path_count = (size_t)query_count * path_len * P2_DIGEST;

    HIP_CHECK(hipMalloc(&d_query_indices, query_indices.size() * sizeof(u64)));
    HIP_CHECK(hipMemcpy(d_query_indices, query_indices.data(), query_indices.size() * sizeof(u64), hipMemcpyHostToDevice));

    HIP_CHECK(hipMalloc(&d_pairs, pair_count * sizeof(u64)));
    if (path_count > 0) {
        HIP_CHECK(hipMalloc(&d_paths, path_count * sizeof(u64)));
    }

    const int threads = 256;

    const int pair_blocks = (int)((pair_count + threads - 1) / threads);
    extract_pair_values_kernel<<<pair_blocks, threads>>>(
        d_layer,
        d_query_indices,
        d_pairs,
        round,
        query_count,
        cols
    );
    HIP_CHECK(hipGetLastError());

    if (path_count > 0) {
        const int path_blocks = (int)((path_count + threads - 1) / threads);
        extract_pair_paths_kernel_v2<<<path_blocks, threads>>>(
            tree.d_tree,
            d_query_indices,
            d_paths,
            rows,
            round,
            query_count,
            path_len
        );
        HIP_CHECK(hipGetLastError());
    }

    std::vector<u64> h_pairs(pair_count);
    std::vector<u64> h_paths(path_count);

    HIP_CHECK(hipMemcpy(h_pairs.data(), d_pairs, pair_count * sizeof(u64), hipMemcpyDeviceToHost));
    if (path_count > 0) {
        HIP_CHECK(hipMemcpy(h_paths.data(), d_paths, path_count * sizeof(u64), hipMemcpyDeviceToHost));
    }

    // Proof order:
    // for each query:
    //   even_values[C]
    //   odd_values[C]
    //   sibling_path[path_len][4]
    for (int q = 0; q < query_count; ++q) {
        for (int i = 0; i < 2 * cols; ++i) {
            proof_openings.push_back(h_pairs[(size_t)q * 2 * cols + i]);
        }

        for (int i = 0; i < path_len * P2_DIGEST; ++i) {
            proof_openings.push_back(h_paths[(size_t)q * path_len * P2_DIGEST + i]);
        }
    }

    HIP_CHECK(hipFree(d_query_indices));
    HIP_CHECK(hipFree(d_pairs));
    if (d_paths) HIP_CHECK(hipFree(d_paths));
    HIP_CHECK(hipFree(tree.d_tree));
}

static void write_qmp_proof_file(
    const std::string& path,
    const QmpHeader& h,
    const std::vector<u64>& roots,
    const std::vector<u64>& final_values,
    const std::vector<u64>& openings
) {
    std::ofstream out(path, std::ios::binary);
    if (!out) throw std::runtime_error("cannot create proof file: " + path);

    const char magic[8] = {'Q', 'M', 'P', 'G', '6', '4', 'V', '1'};
    out.write(magic, 8);

    write_u64_le(out, h.version);
    write_u64_le(out, h.poseidon2_params_fingerprint);
    write_u64_le(out, h.poseidon2_test_vectors_fingerprint);
    write_u64_le(out, h.ntt_root_2_32);
    write_u64_le(out, h.scale_log2);
    write_u64_le(out, h.committed_columns);
    write_u64_le(out, h.layer0_rows);
    write_u64_le(out, h.final_rows);
    write_u64_le(out, h.fri_rounds);
    write_u64_le(out, h.fri_root_count);
    write_u64_le(out, h.fri_query_count);

    write_u64_vec_le(out, roots);
    write_u64_vec_le(out, final_values);
    write_u64_vec_le(out, openings);

    if (!out) throw std::runtime_error("failed while writing proof file: " + path);
}

static void build_qingming_proof_g64(
    const Options& opt,
    const FrozenPoseidon2& p2
) {
    if (opt.final_rows != 1) {
        throw std::runtime_error("QINGMING-PROOF-G64 v1 fixes final_rows = 1");
    }

    if (opt.fri_query_count != QMP_G64_V1_QUERY_COUNT) {
        throw std::runtime_error("QINGMING-PROOF-G64 v1 fixes fri_query_count = 32");
    }

    const double proof_total_t0 = now_ms_host_clock();

    std::vector<u64> raw_matrix = make_committed_matrix(opt.leaf_count, opt.committed_columns);
    check_canonical_matrix(raw_matrix);

    PreparedNttLayer prepared = prepare_layer0_fast_xyz(
        raw_matrix,
        opt.leaf_count,
        opt.committed_columns
    );

    u64* d_matrix = prepared.d_layer0;
    u64* d_ntt_layer0 = prepared.d_layer0_saved;
    GpuNttResult ntt = prepared.ntt;

    const float h2d_ms = prepared.h2d_ms;
    const float ntt_layer0_snapshot_ms = prepared.snapshot_ms;

    const double fri_t0 = now_ms_host_clock();
    GpuFriResult fri = gpu_fri_chain_device_resident(
        d_matrix,
        opt.leaf_count,
        opt.committed_columns,
        opt.final_rows,
        true
    );
    const double fri_wall_ms = now_ms_host_clock() - fri_t0;

    if (fri.final_matrix.size() != (size_t)opt.committed_columns) {
        throw std::runtime_error("proof builder expected final_rows=1 final matrix");
    }

    const double transcript_t0 = now_ms_host_clock();
    std::vector<u64> query_indices = transcript_query_indices(
        fri.roots,
        fri.final_matrix,
        opt.fri_query_count,
        opt.leaf_count,
        p2
    );
    const double transcript_ms = now_ms_host_clock() - transcript_t0;

    const double openings_t0 = now_ms_host_clock();

    // First collect openings per round. append_openings_for_layer emits:
    //   round-major layer buffer:
    //     for q in queries:
    //       even[C], odd[C], path[height-1][4]
    //
    // QMP_G64_V1 proof body is query-major:
    //   for q in queries:
    //     for r in rounds:
    //       even[C], odd[C], path[height_r-1][4]
    //
    // Therefore we collect each round separately and reorder before writing.
    std::vector<std::vector<u64>> openings_by_round;
    openings_by_round.reserve((size_t)fri.rounds);

    u64* d_work = nullptr;
    HIP_CHECK(hipMalloc(&d_work, raw_matrix.size() * sizeof(u64)));

    u64* d_cur = d_ntt_layer0;
    u64* d_next = d_work;

    int rows = opt.leaf_count;

    for (int round = 0; round < fri.rounds; ++round) {
        std::vector<u64> layer_openings;

        append_openings_for_layer(
            layer_openings,
            d_cur,
            rows,
            opt.committed_columns,
            round,
            query_indices
        );

        openings_by_round.push_back(std::move(layer_openings));

        const u64 beta = fri.betas[round];
        const int out_rows = rows / 2;
        const int total_out = out_rows * opt.committed_columns;
        const int threads = 256;
        const int blocks = (total_out + threads - 1) / threads;

        fri_fold_kernel<<<blocks, threads>>>(
            d_cur,
            d_next,
            out_rows,
            opt.committed_columns,
            beta
        );
        HIP_CHECK(hipGetLastError());
        HIP_CHECK(hipDeviceSynchronize());

        std::swap(d_cur, d_next);
        rows = out_rows;
    }

    std::vector<u64> openings;
    openings.reserve(1024);

    for (int q = 0; q < opt.fri_query_count; ++q) {
        for (int round = 0; round < fri.rounds; ++round) {
            const int layer_rows = opt.leaf_count >> round;
            const int height = log2_u64((u64)layer_rows);
            const int path_len = height - 1;
            const size_t entry_len =
                (size_t)2 * (size_t)opt.committed_columns +
                (size_t)path_len * (size_t)P2_DIGEST;

            const std::vector<u64>& layer = openings_by_round[(size_t)round];
            const size_t begin = (size_t)q * entry_len;
            const size_t end = begin + entry_len;

            if (end > layer.size()) {
                throw std::runtime_error("internal opening reorder out of bounds");
            }

            openings.insert(openings.end(), layer.begin() + begin, layer.begin() + end);
        }
    }

    const double openings_ms = now_ms_host_clock() - openings_t0;

    const u64 scale_elements = (u64)opt.leaf_count * (u64)opt.committed_columns;

    QmpHeader header;
    header.version = 1;
    header.poseidon2_params_fingerprint = p2.params_fingerprint;
    header.poseidon2_test_vectors_fingerprint = p2.vectors_fingerprint;
    header.ntt_root_2_32 = G64_ROOT_2_32;
    header.scale_log2 = (u64)log2_exact_u64(scale_elements, "scale_elements");
    header.committed_columns = (u64)opt.committed_columns;
    header.layer0_rows = (u64)opt.leaf_count;
    header.final_rows = 1;
    header.fri_rounds = (u64)fri.rounds;
    header.fri_root_count = (u64)(fri.roots.size() / P2_DIGEST);
    header.fri_query_count = QMP_G64_V1_QUERY_COUNT;

    const double write_t0 = now_ms_host_clock();
    write_qmp_proof_file(
        opt.proof_out,
        header,
        fri.roots,
        fri.final_matrix,
        openings
    );
    const double write_proof_ms = now_ms_host_clock() - write_t0;
    const double proof_total_ms = now_ms_host_clock() - proof_total_t0;

    const float gpu_pipeline_ms = ntt.total_ms + fri.total_ms;
    const float gpu_pipeline_with_snapshot_ms = h2d_ms + ntt.total_ms + ntt_layer0_snapshot_ms + fri.total_ms;

    const int root_count = (int)(fri.roots.size() / P2_DIGEST);
    const u64* final_root = &fri.roots[(size_t)(root_count - 1) * P2_DIGEST];

    std::cout << "QINGMING-PROOF-G64 builder\n";
    std::cout << "status: PASS\n";
    std::cout << "proof_file: " << opt.proof_out << "\n";
    std::cout << "proof_format: QMPG64V1\n";
    std::cout << "operator: qingming-g64-ntt-fast-plus-fri-g64-proof-builder\n";
    std::cout << "merkle_operator: generic-layered-final\n";
    std::cout << "fri_operator: commit-fold-chain\n";
    std::cout << "poseidon2_params_fingerprint: " << hex64(p2.params_fingerprint) << "\n";
    std::cout << "poseidon2_test_vectors_fingerprint: " << hex64(p2.vectors_fingerprint) << "\n";
    std::cout << "scale_log2: " << header.scale_log2 << "\n";
    std::cout << "layer0_rows: " << opt.leaf_count << "\n";
    std::cout << "committed_columns: " << opt.committed_columns << "\n";
    std::cout << "final_rows: 1\n";
    std::cout << "fri_rounds: " << fri.rounds << "\n";
    std::cout << "fri_root_count: " << root_count << "\n";
    std::cout << "fri_query_count: " << opt.fri_query_count << "\n";
    std::cout << "data_residency: large_matrix_h2d_once_then_device_resident_until_final_outputs_and_sampled_openings\n";
    std::cout << "ntt_operator: " << (prepared.used_fast_xyz ? "fast_prelayout_xyz" : "rowwise_radix2_fallback") << "\n";
    std::cout << "h2d_input_ms: " << std::fixed << std::setprecision(3) << h2d_ms << "\n";
    std::cout << "gpu_ntt_total_ms: " << std::fixed << std::setprecision(3) << ntt.total_ms << "\n";
    std::cout << "gpu_ntt_fast_prelayout_ms: " << std::fixed << std::setprecision(3) << prepared.fast_prelayout_ms << "\n";
    std::cout << "gpu_ntt_fast_core_ms: " << std::fixed << std::setprecision(3) << prepared.fast_core_ms << "\n";
    std::cout << "gpu_ntt_bit_reverse_ms: " << std::fixed << std::setprecision(3) << ntt.bit_reverse_ms << "\n";
    std::cout << "gpu_ntt_stages_ms: " << std::fixed << std::setprecision(3) << ntt.stages_ms << "\n";
    std::cout << "ntt_layer0_snapshot_ms: " << std::fixed << std::setprecision(3) << ntt_layer0_snapshot_ms << "\n";
    std::cout << "gpu_fri_total_ms: " << std::fixed << std::setprecision(3) << fri.total_ms << "\n";
    std::cout << "gpu_fri_merkle_ms: " << std::fixed << std::setprecision(3) << fri.merkle_ms << "\n";
    std::cout << "gpu_fri_fold_ms: " << std::fixed << std::setprecision(3) << fri.fold_ms << "\n";
    std::cout << "gpu_pipeline_ms: " << std::fixed << std::setprecision(3) << gpu_pipeline_ms << "\n";
    std::cout << "e2e_device_resident_ms: " << std::fixed << std::setprecision(3) << gpu_pipeline_with_snapshot_ms << "\n";
    std::cout << "fri_wall_ms: " << std::fixed << std::setprecision(3) << fri_wall_ms << "\n";
    std::cout << "transcript_sampling_ms: " << std::fixed << std::setprecision(3) << transcript_ms << "\n";
    std::cout << "proof_opening_extraction_ms: " << std::fixed << std::setprecision(3) << openings_ms << "\n";
    std::cout << "write_proof_ms: " << std::fixed << std::setprecision(3) << write_proof_ms << "\n";
    std::cout << "proof_total_ms: " << std::fixed << std::setprecision(3) << proof_total_ms << "\n";
    std::cout << "fri_roots_fingerprint: " << hex64(fingerprint_values(fri.roots, "QINGMING-PROOF-G64-ROOTS")) << "\n";
    std::cout << "fri_final_values_fingerprint: " << hex64(fingerprint_values(fri.final_matrix, "QINGMING-PROOF-G64-FINAL-VALUES")) << "\n";
    std::cout << "fri_query_indices_fingerprint: " << hex64(fingerprint_values(query_indices, "QINGMING-PROOF-G64-QUERY-INDICES")) << "\n";
    std::cout << "proof_openings_field_elements: " << openings.size() << "\n";
    print_digest("final_root", final_root);

    HIP_CHECK(hipFree(d_work));
    HIP_CHECK(hipFree(d_ntt_layer0));
    HIP_CHECK(hipFree(d_matrix));
}



// -----------------------------
// QINGMING-STARK-G64 v1 baseline
// -----------------------------
//
// This is a fixed compiled AIR profile baseline, not a dynamic AIR DSL.
//
// AIR profile:
//   QINGMING-AIR-GEOCLOCK-G64
//
// Public input layout:
//   public_inputs[0] = transition_ratio
//
// Trace generator:
//   The raw coefficient vector is the degree-1 monomial.
//
//   FAST XYZ path:
//     coeff[1] = 1 over the full SCALE vector.
//
//   Row-wise fallback path:
//     coeff[row=1, col=c] = 1 for every committed column.
//
// The resulting LDE trace is a multiplicative clock.
//
// Constraint:
//   for every LDE row i and column c:
//     trace[(i + LDE) mod rows, c]
//       - transition_ratio * trace[i, c] = 0
//
// Quotient / composition:
//   q[i,c] = alpha * (trace[next,c] - transition_ratio * trace[current,c])
//
// Local verifier checks:
//   sampled quotient relation:
//     q_sample == alpha * (next - transition_ratio * current)
//
// This profile replaces the prior CONSTREG demo profile with a compiled
// non-constant transition AIR while keeping the fixed STARK contract:
//   compiled AIR + trace commitment + randomized quotient +
//   QMPG64V1 quotient FRI + local AIR verifier checks.

static constexpr u64 QM_STARK_TAG_PUBLIC_INPUT = 0x5153505f50554249ULL; // QSP_PUBI
static constexpr u64 QM_STARK_TAG_STATEMENT    = 0x5153505f53544d54ULL; // QSP_STMT
static constexpr u64 QM_STARK_TAG_ALPHA        = 0x5153505f414c5048ULL; // QSP_ALPH
static constexpr u64 QM_STARK_TAG_QUERY        = 0x5153505f51554552ULL; // QSP_QUER
static constexpr int QM_STARK_LDE = 8;

struct StarkRunResult {
    PreparedNttLayer trace;
    GpuRootFromDeviceResult trace_root_result;
    GpuFriResult quotient_fri;

    std::vector<u64> trace_root;
    std::vector<u64> statement_digest;
    std::vector<u64> public_input_digest;
    std::vector<u64> query_indices;
    std::vector<u64> quotient_matrix_check;

    u64 alpha = 0;
    u64 transition_ratio = 0;

    float quotient_eval_ms = 0.0f;
    float quotient_snapshot_ms = 0.0f;
    float gpu_stark_core_ms = 0.0f;
    double transcript_ms = 0.0;
    double local_air_verify_ms = 0.0;
    double total_ms = 0.0;

    bool fri_cpu_gpu_checked = false;
    bool local_air_checked = false;
};

static u64 stark_geoclock_transition_ratio(int rows, int cols, bool fast_xyz) {
    if (fast_xyz) {
        const u64 scale_elements = (u64)rows * (u64)cols;
        const u64 omega_n = g64_pow_u64(G64_ROOT_2_32, (1ULL << 32) / scale_elements);
        return g64_pow_u64(omega_n, (u64)QM_STARK_LDE * (u64)cols);
    }

    const u64 omega_rows = g64_pow_u64(G64_ROOT_2_32, (1ULL << 32) / (u64)rows);
    return g64_pow_u64(omega_rows, (u64)QM_STARK_LDE);
}

static std::vector<u64> make_stark_geoclock_trace_coeffs(int rows, int cols, bool fast_xyz) {
    std::vector<u64> coeffs((size_t)rows * cols, 0);

    if (fast_xyz) {
        // Full-vector monomial: f(n) = omega^n after the SCALE27 NTT.
        if (coeffs.size() < 2) throw std::runtime_error("GEOCLOCK trace needs at least 2 coefficients");
        coeffs[1] = 1;
    } else {
        // Row-wise fallback: one monomial per committed column.
        if (rows < 2) throw std::runtime_error("GEOCLOCK row-wise trace needs rows >= 2");
        for (int c = 0; c < cols; ++c) {
            coeffs[(size_t)cols + c] = 1;
        }
    }

    return coeffs;
}

static void digest_public_inputs_geoclock(
    u64 transition_ratio,
    const FrozenPoseidon2& p2,
    u64 digest[P2_DIGEST]
) {
    std::vector<u64> input;
    input.push_back(QM_STARK_TAG_PUBLIC_INPUT);
    input.push_back(1); // public input count
    input.push_back(transition_ratio);
    cpu_hash_elements(input, DOMAIN_TRANSCRIPT, p2, digest);
}

static void digest_statement_geoclock(
    int scale_log2,
    int rows,
    int cols,
    u64 transition_ratio,
    const u64 public_input_digest[P2_DIGEST],
    const FrozenPoseidon2& p2,
    u64 digest[P2_DIGEST]
) {
    static constexpr u64 AIR_ID0 = 0x514d5f4149525f47ULL; // QM_AIR_G
    static constexpr u64 AIR_ID1 = 0x454f434c4f434b5fULL; // EOCLOCK_
    static constexpr u64 AIR_ID2 = 0x4736345f56315f00ULL; // G64_V1
    static constexpr u64 AIR_ID3 = 0x0000000000000002ULL;

    std::vector<u64> input;
    input.reserve(40);

    input.push_back(QM_STARK_TAG_STATEMENT);
    input.push_back(AIR_ID0);
    input.push_back(AIR_ID1);
    input.push_back(AIR_ID2);
    input.push_back(AIR_ID3);

    for (int i = 0; i < P2_DIGEST; ++i) input.push_back(public_input_digest[i]);

    input.push_back((u64)scale_log2);
    input.push_back((u64)rows);
    input.push_back((u64)cols);
    input.push_back((u64)cols); // trace_columns
    input.push_back((u64)cols); // quotient_columns
    input.push_back((u64)QM_STARK_LDE);
    input.push_back(transition_ratio);

    cpu_hash_elements(input, DOMAIN_TRANSCRIPT, p2, digest);
}

static u64 derive_composition_alpha_geoclock(
    const u64 statement_digest[P2_DIGEST],
    const u64 trace_root[P2_DIGEST],
    const FrozenPoseidon2& p2
) {
    std::vector<u64> input;
    input.reserve(16);

    input.push_back(QM_STARK_TAG_ALPHA);
    for (int i = 0; i < P2_DIGEST; ++i) input.push_back(statement_digest[i]);
    for (int i = 0; i < P2_DIGEST; ++i) input.push_back(trace_root[i]);
    input.push_back(0); // alpha index

    u64 digest[P2_DIGEST];
    cpu_hash_elements(input, DOMAIN_TRANSCRIPT, p2, digest);
    return digest[0];
}

static std::vector<u64> stark_query_indices(
    const u64 statement_digest[P2_DIGEST],
    const u64 trace_root[P2_DIGEST],
    const std::vector<u64>& quotient_roots,
    const std::vector<u64>& final_values,
    int query_count,
    int rows,
    const FrozenPoseidon2& p2
) {
    std::vector<u64> out;
    out.reserve(query_count);

    for (int q = 0; q < query_count; ++q) {
        std::vector<u64> input;
        input.reserve(quotient_roots.size() + final_values.size() + 16);

        input.push_back(QM_STARK_TAG_QUERY);
        for (int i = 0; i < P2_DIGEST; ++i) input.push_back(statement_digest[i]);
        for (int i = 0; i < P2_DIGEST; ++i) input.push_back(trace_root[i]);
        for (u64 x : quotient_roots) input.push_back(x);
        for (u64 x : final_values) input.push_back(x);
        input.push_back((u64)q);

        u64 digest[P2_DIGEST];
        cpu_hash_elements(input, DOMAIN_TRANSCRIPT, p2, digest);
        out.push_back(digest[0] & ((u64)rows - 1));
    }

    return out;
}

__global__ void stark_geoclock_quotient_kernel(
    const u64* __restrict__ trace,
    u64* __restrict__ quotient,
    int rows,
    int cols,
    u64 alpha,
    u64 transition_ratio
) {
    const int idx = blockIdx.x * blockDim.x + threadIdx.x;
    const int total = rows * cols;
    if (idx >= total) return;

    const int r = idx / cols;
    const int c = idx - r * cols;
    const int next_r = (r + QM_STARK_LDE) & (rows - 1);

    const u64 cur = trace[(size_t)r * cols + c];
    const u64 nxt = trace[(size_t)next_r * cols + c];

    const u64 constraint = g64_sub(nxt, g64_mul(transition_ratio, cur));
    quotient[(size_t)r * cols + c] = g64_mul(alpha, constraint);
}

__global__ void stark_extract_trace_quotient_samples_kernel(
    const u64* __restrict__ trace,
    const u64* __restrict__ quotient,
    const u64* __restrict__ query_indices,
    u64* __restrict__ out_current,
    u64* __restrict__ out_next,
    u64* __restrict__ out_quotient,
    int query_count,
    int rows,
    int cols
) {
    const int idx = blockIdx.x * blockDim.x + threadIdx.x;
    const int total = query_count * cols;
    if (idx >= total) return;

    const int q = idx / cols;
    const int c = idx - q * cols;

    const int r = (int)query_indices[q];
    const int next_r = (r + QM_STARK_LDE) & (rows - 1);

    out_current[(size_t)q * cols + c] = trace[(size_t)r * cols + c];
    out_next[(size_t)q * cols + c] = trace[(size_t)next_r * cols + c];
    out_quotient[(size_t)q * cols + c] = quotient[(size_t)r * cols + c];
}

static void local_air_verify_geoclock_samples(
    const std::vector<u64>& current,
    const std::vector<u64>& next,
    const std::vector<u64>& quotient,
    int query_count,
    int cols,
    u64 alpha,
    u64 transition_ratio
) {
    if (current.size() != (size_t)query_count * cols ||
        next.size() != (size_t)query_count * cols ||
        quotient.size() != (size_t)query_count * cols) {
        throw std::runtime_error("bad sample vector size");
    }

    for (int q = 0; q < query_count; ++q) {
        for (int c = 0; c < cols; ++c) {
            const size_t p = (size_t)q * cols + c;

            const u64 constraint = g64_sub(next[p], g64_mul(transition_ratio, current[p]));
            const u64 lhs = g64_mul(alpha, constraint);
            const u64 rhs = quotient[p];

            if (lhs != rhs) {
                std::ostringstream os;
                os << "GEOCLOCK quotient relation mismatch q=" << q
                   << " col=" << c
                   << " lhs=" << hex64(lhs)
                   << " rhs=" << hex64(rhs)
                   << " current=" << hex64(current[p])
                   << " next=" << hex64(next[p])
                   << " ratio=" << hex64(transition_ratio);
                throw std::runtime_error(os.str());
            }
        }
    }
}

static StarkRunResult run_qingming_stark_g64_v1(
    const Options& opt,
    const FrozenPoseidon2& p2,
    bool full_correctness
) {
    if (opt.final_rows != 1) {
        throw std::runtime_error("QINGMING-STARK-G64 v1 fixes final_rows = 1");
    }

    if (opt.fri_query_count != QMP_G64_V1_QUERY_COUNT) {
        throw std::runtime_error("QINGMING-STARK-G64 v1 fixes fri_query_count = 32");
    }

    const double total_t0 = now_ms_host_clock();

    const u64 scale_elements = (u64)opt.leaf_count * (u64)opt.committed_columns;
    const int scale_log2 = log2_exact_u64(scale_elements, "scale_elements");
    const bool fast_path = (scale_elements == QM_NTT_FAST_N && opt.committed_columns == 16);

    const u64 transition_ratio = stark_geoclock_transition_ratio(
        opt.leaf_count,
        opt.committed_columns,
        fast_path
    );

    std::vector<u64> trace_coeffs = make_stark_geoclock_trace_coeffs(
        opt.leaf_count,
        opt.committed_columns,
        fast_path
    );

    StarkRunResult out;
    out.transition_ratio = transition_ratio;

    out.trace = prepare_layer0_fast_xyz(
        trace_coeffs,
        opt.leaf_count,
        opt.committed_columns
    );

    out.trace_root_result = gpu_merkle_root_from_device_matrix(
        out.trace.d_layer0_saved,
        opt.leaf_count,
        opt.committed_columns
    );

    out.trace_root.assign(P2_DIGEST, 0);
    for (int i = 0; i < P2_DIGEST; ++i) out.trace_root[i] = out.trace_root_result.root[i];

    u64 public_digest[P2_DIGEST];
    u64 statement_digest[P2_DIGEST];

    digest_public_inputs_geoclock(transition_ratio, p2, public_digest);
    digest_statement_geoclock(
        scale_log2,
        opt.leaf_count,
        opt.committed_columns,
        transition_ratio,
        public_digest,
        p2,
        statement_digest
    );

    out.public_input_digest.assign(public_digest, public_digest + P2_DIGEST);
    out.statement_digest.assign(statement_digest, statement_digest + P2_DIGEST);
    out.alpha = derive_composition_alpha_geoclock(statement_digest, out.trace_root_result.root, p2);

    u64* d_quotient = nullptr;
    u64* d_quotient_saved = nullptr;
    HIP_CHECK(hipMalloc(&d_quotient, trace_coeffs.size() * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_quotient_saved, trace_coeffs.size() * sizeof(u64)));

    hipEvent_t qe_start, qe_stop, qs_start, qs_stop;
    HIP_CHECK(hipEventCreate(&qe_start));
    HIP_CHECK(hipEventCreate(&qe_stop));
    HIP_CHECK(hipEventCreate(&qs_start));
    HIP_CHECK(hipEventCreate(&qs_stop));

    const int threads = 256;
    const int total = opt.leaf_count * opt.committed_columns;
    const int blocks = (total + threads - 1) / threads;

    HIP_CHECK(hipEventRecord(qe_start));
    stark_geoclock_quotient_kernel<<<blocks, threads>>>(
        out.trace.d_layer0_saved,
        d_quotient,
        opt.leaf_count,
        opt.committed_columns,
        out.alpha,
        transition_ratio
    );
    HIP_CHECK(hipGetLastError());
    HIP_CHECK(hipEventRecord(qe_stop));
    HIP_CHECK(hipEventSynchronize(qe_stop));
    out.quotient_eval_ms = event_ms(qe_start, qe_stop);

    HIP_CHECK(hipEventRecord(qs_start));
    HIP_CHECK(hipMemcpy(d_quotient_saved, d_quotient, trace_coeffs.size() * sizeof(u64), hipMemcpyDeviceToDevice));
    HIP_CHECK(hipEventRecord(qs_stop));
    HIP_CHECK(hipEventSynchronize(qs_stop));
    out.quotient_snapshot_ms = event_ms(qs_start, qs_stop);

    out.quotient_fri = gpu_fri_chain_device_resident(
        d_quotient,
        opt.leaf_count,
        opt.committed_columns,
        opt.final_rows,
        true
    );

    const double transcript_t0 = now_ms_host_clock();
    out.query_indices = stark_query_indices(
        statement_digest,
        out.trace_root_result.root,
        out.quotient_fri.roots,
        out.quotient_fri.final_matrix,
        opt.fri_query_count,
        opt.leaf_count,
        p2
    );
    out.transcript_ms = now_ms_host_clock() - transcript_t0;

    const double local_t0 = now_ms_host_clock();

    u64* d_query_indices = nullptr;
    u64* d_current = nullptr;
    u64* d_next = nullptr;
    u64* d_q = nullptr;

    const size_t sample_values = (size_t)opt.fri_query_count * opt.committed_columns;

    HIP_CHECK(hipMalloc(&d_query_indices, out.query_indices.size() * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_current, sample_values * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_next, sample_values * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_q, sample_values * sizeof(u64)));

    HIP_CHECK(hipMemcpy(d_query_indices, out.query_indices.data(), out.query_indices.size() * sizeof(u64), hipMemcpyHostToDevice));

    const int sample_total = opt.fri_query_count * opt.committed_columns;
    const int sample_blocks = (sample_total + threads - 1) / threads;

    stark_extract_trace_quotient_samples_kernel<<<sample_blocks, threads>>>(
        out.trace.d_layer0_saved,
        d_quotient_saved,
        d_query_indices,
        d_current,
        d_next,
        d_q,
        opt.fri_query_count,
        opt.leaf_count,
        opt.committed_columns
    );
    HIP_CHECK(hipGetLastError());

    std::vector<u64> h_current(sample_values);
    std::vector<u64> h_next(sample_values);
    std::vector<u64> h_q(sample_values);

    HIP_CHECK(hipMemcpy(h_current.data(), d_current, sample_values * sizeof(u64), hipMemcpyDeviceToHost));
    HIP_CHECK(hipMemcpy(h_next.data(), d_next, sample_values * sizeof(u64), hipMemcpyDeviceToHost));
    HIP_CHECK(hipMemcpy(h_q.data(), d_q, sample_values * sizeof(u64), hipMemcpyDeviceToHost));

    local_air_verify_geoclock_samples(
        h_current,
        h_next,
        h_q,
        opt.fri_query_count,
        opt.committed_columns,
        out.alpha,
        transition_ratio
    );

    out.local_air_verify_ms = now_ms_host_clock() - local_t0;
    out.local_air_checked = true;

    if (full_correctness) {
        out.quotient_matrix_check.assign(trace_coeffs.size(), 0);
        HIP_CHECK(hipMemcpy(out.quotient_matrix_check.data(), d_quotient_saved, trace_coeffs.size() * sizeof(u64), hipMemcpyDeviceToHost));

        run_fri_correctness(
            out.quotient_matrix_check,
            opt.leaf_count,
            opt.committed_columns,
            opt.final_rows,
            p2,
            out.quotient_fri
        );

        out.fri_cpu_gpu_checked = true;
    }

    out.gpu_stark_core_ms =
        out.trace.h2d_ms +
        out.trace.ntt.total_ms +
        out.trace.snapshot_ms +
        out.trace_root_result.total_ms +
        out.quotient_eval_ms +
        out.quotient_snapshot_ms +
        out.quotient_fri.total_ms;

    out.total_ms = now_ms_host_clock() - total_t0;

    HIP_CHECK(hipFree(d_query_indices));
    HIP_CHECK(hipFree(d_current));
    HIP_CHECK(hipFree(d_next));
    HIP_CHECK(hipFree(d_q));

    HIP_CHECK(hipEventDestroy(qe_start));
    HIP_CHECK(hipEventDestroy(qe_stop));
    HIP_CHECK(hipEventDestroy(qs_start));
    HIP_CHECK(hipEventDestroy(qs_stop));

    HIP_CHECK(hipFree(d_quotient_saved));
    HIP_CHECK(hipFree(d_quotient));
    HIP_CHECK(hipFree(out.trace.d_layer0_saved));
    HIP_CHECK(hipFree(out.trace.d_layer0));

    return out;
}

static void report_qingming_stark_g64_v1(
    const char* title,
    const Options& opt,
    const FrozenPoseidon2& p2,
    const StarkRunResult& r,
    bool correctness
) {
    const int root_count = (int)(r.quotient_fri.roots.size() / P2_DIGEST);
    const u64* final_root = &r.quotient_fri.roots[(size_t)(root_count - 1) * P2_DIGEST];
    const u64* quotient_root = &r.quotient_fri.roots[0];

    const u64 scale_elements = (u64)opt.leaf_count * (u64)opt.committed_columns;
    const int scale_log2 = log2_exact_u64(scale_elements, "scale_elements");

    std::cout << title << "\n";
    std::cout << "status: PASS\n";
    std::cout << "stark_profile: QINGMING-STARK-G64\n";
    std::cout << "air_profile: QINGMING-AIR-GEOCLOCK-G64\n";
    std::cout << "statement: public_input[0]=transition_ratio and trace_next - transition_ratio * trace_current = 0\n";
    std::cout << "field: Goldilocks/G64\n";
    std::cout << "p: " << G64_P << "\n";
    std::cout << "hash: QINGMING-POSEIDON2-G64\n";
    std::cout << "poseidon2_params_fingerprint: " << hex64(p2.params_fingerprint) << "\n";
    std::cout << "poseidon2_test_vectors_fingerprint: " << hex64(p2.vectors_fingerprint) << "\n";
    std::cout << "scale_log2: " << scale_log2 << "\n";
    std::cout << "lde_factor: " << QM_STARK_LDE << "\n";
    std::cout << "layer0_rows: " << opt.leaf_count << "\n";
    std::cout << "trace_columns: " << opt.committed_columns << "\n";
    std::cout << "quotient_columns: " << opt.committed_columns << "\n";
    std::cout << "final_rows: " << opt.final_rows << "\n";
    std::cout << "fri_rounds: " << r.quotient_fri.rounds << "\n";
    std::cout << "fri_root_count: " << root_count << "\n";
    std::cout << "fri_query_count: " << opt.fri_query_count << "\n";
    std::cout << "ntt_operator: " << (r.trace.used_fast_xyz ? "fast_prelayout_xyz" : "rowwise_radix2_fallback") << "\n";
    std::cout << "public_input_layout: [transition_ratio]\n";
    std::cout << "transition_ratio: " << hex64(r.transition_ratio) << "\n";

    std::cout << "trace_h2d_ms: " << std::fixed << std::setprecision(3) << r.trace.h2d_ms << "\n";
    std::cout << "trace_ntt_total_ms: " << std::fixed << std::setprecision(3) << r.trace.ntt.total_ms << "\n";
    std::cout << "trace_ntt_fast_prelayout_ms: " << std::fixed << std::setprecision(3) << r.trace.fast_prelayout_ms << "\n";
    std::cout << "trace_ntt_fast_core_ms: " << std::fixed << std::setprecision(3) << r.trace.fast_core_ms << "\n";
    std::cout << "trace_layer0_snapshot_ms: " << std::fixed << std::setprecision(3) << r.trace.snapshot_ms << "\n";
    std::cout << "trace_merkle_commit_ms: " << std::fixed << std::setprecision(3) << r.trace_root_result.total_ms << "\n";
    std::cout << "quotient_eval_ms: " << std::fixed << std::setprecision(3) << r.quotient_eval_ms << "\n";
    std::cout << "quotient_snapshot_ms: " << std::fixed << std::setprecision(3) << r.quotient_snapshot_ms << "\n";
    std::cout << "quotient_fri_total_ms: " << std::fixed << std::setprecision(3) << r.quotient_fri.total_ms << "\n";
    std::cout << "quotient_fri_merkle_ms: " << std::fixed << std::setprecision(3) << r.quotient_fri.merkle_ms << "\n";
    std::cout << "quotient_fri_fold_ms: " << std::fixed << std::setprecision(3) << r.quotient_fri.fold_ms << "\n";
    std::cout << "transcript_ms: " << std::fixed << std::setprecision(3) << r.transcript_ms << "\n";
    std::cout << "local_air_verify_ms: " << std::fixed << std::setprecision(3) << r.local_air_verify_ms << "\n";
    std::cout << "gpu_stark_core_ms: " << std::fixed << std::setprecision(3) << r.gpu_stark_core_ms << "\n";
    std::cout << "stark_total_ms: " << std::fixed << std::setprecision(3) << r.total_ms << "\n";

    std::cout << "public_input_digest_fingerprint: " << hex64(fingerprint_values(r.public_input_digest, "QINGMING-STARK-PUBLIC-INPUT-DIGEST")) << "\n";
    std::cout << "statement_digest_fingerprint: " << hex64(fingerprint_values(r.statement_digest, "QINGMING-STARK-STATEMENT-DIGEST")) << "\n";
    std::cout << "trace_root_fingerprint: " << hex64(fingerprint_values(r.trace_root, "QINGMING-STARK-TRACE-ROOT")) << "\n";
    std::cout << "quotient_roots_fingerprint: " << hex64(fingerprint_values(r.quotient_fri.roots, "QINGMING-STARK-QUOTIENT-ROOTS")) << "\n";
    std::cout << "query_indices_fingerprint: " << hex64(fingerprint_values(r.query_indices, "QINGMING-STARK-QUERY-INDICES")) << "\n";
    std::cout << "composition_alpha: " << hex64(r.alpha) << "\n";

    std::cout << "local_air_checks: " << (r.local_air_checked ? "PASS" : "SKIPPED") << "\n";
    std::cout << "quotient_relation_checks: " << (r.local_air_checked ? "PASS" : "SKIPPED") << "\n";
    std::cout << "qmpg64v1_cpu_gpu_fri_check: " << (r.fri_cpu_gpu_checked ? "PASS" : "SKIPPED") << "\n";

    print_digest("trace_root", r.trace_root.data());
    print_digest("quotient_root", quotient_root);
    print_digest("final_root", final_root);
}



// -----------------------------
// QSPG64 full STARK proof builder
// -----------------------------

static constexpr u64 QSPG64_AIR_PROFILE_GEOCLOCK = 1;

__global__ void extract_qsp_trace_values_kernel(
    const u64* __restrict__ trace,
    const u64* __restrict__ query_indices,
    u64* __restrict__ out_current,
    u64* __restrict__ out_next,
    int query_count,
    int rows,
    int cols
) {
    const int idx = blockIdx.x * blockDim.x + threadIdx.x;
    const int total = query_count * cols;
    if (idx >= total) return;

    const int q = idx / cols;
    const int c = idx - q * cols;

    const u64 cur_r = query_indices[q];
    const u64 next_r = (cur_r + QM_STARK_LDE) & ((u64)rows - 1ULL);

    out_current[(size_t)q * cols + c] = trace[(size_t)cur_r * cols + c];
    out_next[(size_t)q * cols + c] = trace[(size_t)next_r * cols + c];
}

__global__ void extract_qsp_trace_paths_kernel(
    const u64* __restrict__ tree,
    const u64* __restrict__ query_indices,
    u64* __restrict__ out_current_paths,
    u64* __restrict__ out_next_paths,
    int rows,
    int query_count,
    int height
) {
    const int idx = blockIdx.x * blockDim.x + threadIdx.x;
    const int total = query_count * height * P2_DIGEST;
    if (idx >= total) return;

    const int d = idx % P2_DIGEST;
    const int t = idx / P2_DIGEST;
    const int level = t % height;
    const int q = t / height;

    const u64 cur_row = query_indices[q];
    const u64 next_row = (cur_row + QM_STARK_LDE) & ((u64)rows - 1ULL);

    u64 level_offset = 0;
    if (level > 0) {
        level_offset = (u64)2 * (u64)rows - ((u64)rows >> (level - 1));
    }

    const u64 cur_sibling = (cur_row >> level) ^ 1ULL;
    const u64 next_sibling = (next_row >> level) ^ 1ULL;

    out_current_paths[(size_t)q * height * P2_DIGEST + (size_t)level * P2_DIGEST + d] =
        tree[(size_t)(level_offset + cur_sibling) * P2_DIGEST + d];

    out_next_paths[(size_t)q * height * P2_DIGEST + (size_t)level * P2_DIGEST + d] =
        tree[(size_t)(level_offset + next_sibling) * P2_DIGEST + d];
}

static void append_qsp_trace_openings(
    std::vector<u64>& trace_openings,
    const u64* d_trace,
    int rows,
    int cols,
    const std::vector<u64>& query_indices
) {
    const int query_count = (int)query_indices.size();
    const int height = log2_u64((u64)rows);

    DeviceTreeForProof tree = gpu_build_full_tree_device_for_proof(d_trace, rows, cols);

    u64* d_query_indices = nullptr;
    u64* d_current = nullptr;
    u64* d_next = nullptr;
    u64* d_current_paths = nullptr;
    u64* d_next_paths = nullptr;

    const size_t values_count = (size_t)query_count * cols;
    const size_t path_count = (size_t)query_count * height * P2_DIGEST;

    HIP_CHECK(hipMalloc(&d_query_indices, query_indices.size() * sizeof(u64)));
    HIP_CHECK(hipMemcpy(d_query_indices, query_indices.data(), query_indices.size() * sizeof(u64), hipMemcpyHostToDevice));
    HIP_CHECK(hipMalloc(&d_current, values_count * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_next, values_count * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_current_paths, path_count * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_next_paths, path_count * sizeof(u64)));

    const int threads = 256;
    const int value_blocks = (int)((values_count + threads - 1) / threads);
    extract_qsp_trace_values_kernel<<<value_blocks, threads>>>(
        d_trace,
        d_query_indices,
        d_current,
        d_next,
        query_count,
        rows,
        cols
    );
    HIP_CHECK(hipGetLastError());

    const int path_blocks = (int)((path_count + threads - 1) / threads);
    extract_qsp_trace_paths_kernel<<<path_blocks, threads>>>(
        tree.d_tree,
        d_query_indices,
        d_current_paths,
        d_next_paths,
        rows,
        query_count,
        height
    );
    HIP_CHECK(hipGetLastError());

    std::vector<u64> h_current(values_count);
    std::vector<u64> h_next(values_count);
    std::vector<u64> h_current_paths(path_count);
    std::vector<u64> h_next_paths(path_count);

    HIP_CHECK(hipMemcpy(h_current.data(), d_current, values_count * sizeof(u64), hipMemcpyDeviceToHost));
    HIP_CHECK(hipMemcpy(h_next.data(), d_next, values_count * sizeof(u64), hipMemcpyDeviceToHost));
    HIP_CHECK(hipMemcpy(h_current_paths.data(), d_current_paths, path_count * sizeof(u64), hipMemcpyDeviceToHost));
    HIP_CHECK(hipMemcpy(h_next_paths.data(), d_next_paths, path_count * sizeof(u64), hipMemcpyDeviceToHost));

    // QSP trace opening order:
    // for q in queries:
    //   current_values[C]
    //   current_path[height][4]
    //   next_values[C]
    //   next_path[height][4]
    for (int q = 0; q < query_count; ++q) {
        trace_openings.insert(
            trace_openings.end(),
            h_current.begin() + (size_t)q * cols,
            h_current.begin() + (size_t)(q + 1) * cols
        );

        trace_openings.insert(
            trace_openings.end(),
            h_current_paths.begin() + (size_t)q * height * P2_DIGEST,
            h_current_paths.begin() + (size_t)(q + 1) * height * P2_DIGEST
        );

        trace_openings.insert(
            trace_openings.end(),
            h_next.begin() + (size_t)q * cols,
            h_next.begin() + (size_t)(q + 1) * cols
        );

        trace_openings.insert(
            trace_openings.end(),
            h_next_paths.begin() + (size_t)q * height * P2_DIGEST,
            h_next_paths.begin() + (size_t)(q + 1) * height * P2_DIGEST
        );
    }

    HIP_CHECK(hipFree(d_query_indices));
    HIP_CHECK(hipFree(d_current));
    HIP_CHECK(hipFree(d_next));
    HIP_CHECK(hipFree(d_current_paths));
    HIP_CHECK(hipFree(d_next_paths));
    HIP_CHECK(hipFree(tree.d_tree));
}


static void append_qsp_trace_openings_retained(
    std::vector<u64>& trace_openings,
    const u64* d_trace,
    const DeviceTreeForProof& tree,
    int rows,
    int cols,
    const std::vector<u64>& query_indices
) {
    const int query_count = (int)query_indices.size();
    const int height = log2_u64((u64)rows);

    u64* d_query_indices = nullptr;
    u64* d_current = nullptr;
    u64* d_next = nullptr;
    u64* d_current_paths = nullptr;
    u64* d_next_paths = nullptr;

    const size_t values_count = (size_t)query_count * cols;
    const size_t path_count = (size_t)query_count * height * P2_DIGEST;

    HIP_CHECK(hipMalloc(&d_query_indices, query_indices.size() * sizeof(u64)));
    HIP_CHECK(hipMemcpy(d_query_indices, query_indices.data(), query_indices.size() * sizeof(u64), hipMemcpyHostToDevice));
    HIP_CHECK(hipMalloc(&d_current, values_count * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_next, values_count * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_current_paths, path_count * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_next_paths, path_count * sizeof(u64)));

    const int threads = 256;
    const int value_blocks = (int)((values_count + threads - 1) / threads);
    extract_qsp_trace_values_kernel<<<value_blocks, threads>>>(
        d_trace,
        d_query_indices,
        d_current,
        d_next,
        query_count,
        rows,
        cols
    );
    HIP_CHECK(hipGetLastError());

    const int path_blocks = (int)((path_count + threads - 1) / threads);
    extract_qsp_trace_paths_kernel<<<path_blocks, threads>>>(
        tree.d_tree,
        d_query_indices,
        d_current_paths,
        d_next_paths,
        rows,
        query_count,
        height
    );
    HIP_CHECK(hipGetLastError());

    std::vector<u64> h_current(values_count);
    std::vector<u64> h_next(values_count);
    std::vector<u64> h_current_paths(path_count);
    std::vector<u64> h_next_paths(path_count);

    HIP_CHECK(hipMemcpy(h_current.data(), d_current, values_count * sizeof(u64), hipMemcpyDeviceToHost));
    HIP_CHECK(hipMemcpy(h_next.data(), d_next, values_count * sizeof(u64), hipMemcpyDeviceToHost));
    HIP_CHECK(hipMemcpy(h_current_paths.data(), d_current_paths, path_count * sizeof(u64), hipMemcpyDeviceToHost));
    HIP_CHECK(hipMemcpy(h_next_paths.data(), d_next_paths, path_count * sizeof(u64), hipMemcpyDeviceToHost));

    for (int q = 0; q < query_count; ++q) {
        trace_openings.insert(
            trace_openings.end(),
            h_current.begin() + (size_t)q * cols,
            h_current.begin() + (size_t)(q + 1) * cols
        );

        trace_openings.insert(
            trace_openings.end(),
            h_current_paths.begin() + (size_t)q * height * P2_DIGEST,
            h_current_paths.begin() + (size_t)(q + 1) * height * P2_DIGEST
        );

        trace_openings.insert(
            trace_openings.end(),
            h_next.begin() + (size_t)q * cols,
            h_next.begin() + (size_t)(q + 1) * cols
        );

        trace_openings.insert(
            trace_openings.end(),
            h_next_paths.begin() + (size_t)q * height * P2_DIGEST,
            h_next_paths.begin() + (size_t)(q + 1) * height * P2_DIGEST
        );
    }

    HIP_CHECK(hipFree(d_query_indices));
    HIP_CHECK(hipFree(d_current));
    HIP_CHECK(hipFree(d_next));
    HIP_CHECK(hipFree(d_current_paths));
    HIP_CHECK(hipFree(d_next_paths));
}


static void write_qsp_proof_file(
    const std::string& path,
    const FrozenPoseidon2& p2,
    int scale_log2,
    int rows,
    int cols,
    int final_rows,
    int fri_rounds,
    int fri_root_count,
    int fri_query_count,
    u64 transition_ratio,
    u64 alpha,
    const std::vector<u64>& public_input_digest,
    const std::vector<u64>& statement_digest,
    const std::vector<u64>& trace_root,
    const std::vector<u64>& quotient_roots,
    const std::vector<u64>& final_values,
    const std::vector<u64>& quotient_openings,
    const std::vector<u64>& trace_openings
) {
    std::ofstream out(path, std::ios::binary);
    if (!out) throw std::runtime_error("cannot create proof file: " + path);

    const char magic[8] = {'Q', 'S', 'P', 'G', '6', '4', '\0', '\0'};
    out.write(magic, 8);

    write_u64_le(out, 1); // internal format revision, file name and docs are tag-versioned
    write_u64_le(out, p2.params_fingerprint);
    write_u64_le(out, p2.vectors_fingerprint);
    write_u64_le(out, G64_ROOT_2_32);
    write_u64_le(out, (u64)scale_log2);
    write_u64_le(out, (u64)QM_STARK_LDE);
    write_u64_le(out, (u64)rows);
    write_u64_le(out, (u64)cols); // trace_columns
    write_u64_le(out, (u64)cols); // quotient_columns
    write_u64_le(out, (u64)final_rows);
    write_u64_le(out, (u64)fri_rounds);
    write_u64_le(out, (u64)fri_root_count);
    write_u64_le(out, (u64)fri_query_count);
    write_u64_le(out, QSPG64_AIR_PROFILE_GEOCLOCK);
    write_u64_le(out, 1); // public input count
    write_u64_le(out, transition_ratio);
    write_u64_le(out, alpha);

    write_u64_vec_le(out, public_input_digest);
    write_u64_vec_le(out, statement_digest);
    write_u64_vec_le(out, trace_root);
    write_u64_vec_le(out, quotient_roots);
    write_u64_vec_le(out, final_values);
    write_u64_vec_le(out, quotient_openings);
    write_u64_vec_le(out, trace_openings);

    if (!out) throw std::runtime_error("failed while writing proof file: " + path);
}

static void build_qingming_stark_proof_g64(const Options& opt, const FrozenPoseidon2& p2) {
    const double total_t0 = now_ms_host_clock();

    if (opt.final_rows != 1) throw std::runtime_error("QSPG64 fixes final_rows = 1");
    if (opt.fri_query_count != QMP_G64_V1_QUERY_COUNT) throw std::runtime_error("QSPG64 fixes fri_query_count = 32");

    const u64 scale_elements = (u64)opt.leaf_count * (u64)opt.committed_columns;
    const int scale_log2 = log2_exact_u64(scale_elements, "scale_elements");
    const bool fast_path = (scale_elements == QM_NTT_FAST_N && opt.committed_columns == 16);

    const u64 transition_ratio = stark_geoclock_transition_ratio(
        opt.leaf_count,
        opt.committed_columns,
        fast_path
    );

    std::vector<u64> trace_coeffs = make_stark_geoclock_trace_coeffs(
        opt.leaf_count,
        opt.committed_columns,
        fast_path
    );

    PreparedNttLayer trace = prepare_layer0_fast_xyz(
        trace_coeffs,
        opt.leaf_count,
        opt.committed_columns
    );

    DeviceTreeForProof trace_tree = gpu_build_full_tree_device_for_proof(
        trace.d_layer0_saved,
        opt.leaf_count,
        opt.committed_columns
    );

    u64 public_digest[P2_DIGEST];
    u64 statement_digest_arr[P2_DIGEST];

    digest_public_inputs_geoclock(transition_ratio, p2, public_digest);
    digest_statement_geoclock(
        scale_log2,
        opt.leaf_count,
        opt.committed_columns,
        transition_ratio,
        public_digest,
        p2,
        statement_digest_arr
    );

    std::vector<u64> public_digest_vec(public_digest, public_digest + P2_DIGEST);
    std::vector<u64> statement_digest_vec(statement_digest_arr, statement_digest_arr + P2_DIGEST);
    std::vector<u64> trace_root_vec(trace_tree.root, trace_tree.root + P2_DIGEST);

    const u64 alpha = derive_composition_alpha_geoclock(statement_digest_arr, trace_tree.root, p2);

    u64* d_quotient = nullptr;
    u64* d_quotient_saved = nullptr;
    HIP_CHECK(hipMalloc(&d_quotient, trace_coeffs.size() * sizeof(u64)));
    HIP_CHECK(hipMalloc(&d_quotient_saved, trace_coeffs.size() * sizeof(u64)));

    hipEvent_t qe_start, qe_stop, qs_start, qs_stop;
    HIP_CHECK(hipEventCreate(&qe_start));
    HIP_CHECK(hipEventCreate(&qe_stop));
    HIP_CHECK(hipEventCreate(&qs_start));
    HIP_CHECK(hipEventCreate(&qs_stop));

    const int threads = 256;
    const int total = opt.leaf_count * opt.committed_columns;
    const int blocks = (total + threads - 1) / threads;

    HIP_CHECK(hipEventRecord(qe_start));
    stark_geoclock_quotient_kernel<<<blocks, threads>>>(
        trace.d_layer0_saved,
        d_quotient,
        opt.leaf_count,
        opt.committed_columns,
        alpha,
        transition_ratio
    );
    HIP_CHECK(hipGetLastError());
    HIP_CHECK(hipEventRecord(qe_stop));
    HIP_CHECK(hipEventSynchronize(qe_stop));
    const float quotient_eval_ms = event_ms(qe_start, qe_stop);

    HIP_CHECK(hipEventRecord(qs_start));
    HIP_CHECK(hipMemcpy(d_quotient_saved, d_quotient, trace_coeffs.size() * sizeof(u64), hipMemcpyDeviceToDevice));
    HIP_CHECK(hipEventRecord(qs_stop));
    HIP_CHECK(hipEventSynchronize(qs_stop));
    const float quotient_snapshot_ms = event_ms(qs_start, qs_stop);

    GpuFriRetainedResult fri = gpu_fri_chain_device_resident_retained(
        d_quotient,
        opt.leaf_count,
        opt.committed_columns,
        opt.final_rows,
        true
    );

    const double transcript_t0 = now_ms_host_clock();
    std::vector<u64> query_indices = stark_query_indices(
        statement_digest_arr,
        trace_tree.root,
        fri.roots,
        fri.final_matrix,
        opt.fri_query_count,
        opt.leaf_count,
        p2
    );
    const double transcript_ms = now_ms_host_clock() - transcript_t0;

    const double openings_t0 = now_ms_host_clock();

    std::vector<std::vector<u64>> openings_by_round;
    openings_by_round.reserve((size_t)fri.rounds);

    u64* d_work = nullptr;
    HIP_CHECK(hipMalloc(&d_work, trace_coeffs.size() * sizeof(u64)));

    u64* d_cur = d_quotient_saved;
    u64* d_next = d_work;
    int rows = opt.leaf_count;

    for (int round = 0; round < fri.rounds; ++round) {
        std::vector<u64> layer_openings;
        append_openings_for_layer_retained(
            layer_openings,
            d_cur,
            fri.retained_trees[(size_t)round],
            rows,
            opt.committed_columns,
            round,
            query_indices
        );
        openings_by_round.push_back(std::move(layer_openings));

        const u64 beta = fri.betas[(size_t)round];
        const int out_rows = rows / 2;
        const int total_out = out_rows * opt.committed_columns;
        const int fold_blocks = (total_out + threads - 1) / threads;

        fri_fold_kernel<<<fold_blocks, threads>>>(
            d_cur,
            d_next,
            out_rows,
            opt.committed_columns,
            beta
        );
        HIP_CHECK(hipGetLastError());
        HIP_CHECK(hipDeviceSynchronize());

        std::swap(d_cur, d_next);
        rows = out_rows;
    }

    std::vector<u64> quotient_openings;
    quotient_openings.reserve(1024);

    for (int q = 0; q < opt.fri_query_count; ++q) {
        for (int round = 0; round < fri.rounds; ++round) {
            const int layer_rows = opt.leaf_count >> round;
            const int height = log2_u64((u64)layer_rows);
            const int path_len = height - 1;
            const size_t entry_len =
                (size_t)2 * (size_t)opt.committed_columns +
                (size_t)path_len * (size_t)P2_DIGEST;

            const std::vector<u64>& layer = openings_by_round[(size_t)round];
            const size_t begin = (size_t)q * entry_len;
            const size_t end = begin + entry_len;

            if (end > layer.size()) throw std::runtime_error("internal quotient opening reorder out of bounds");
            quotient_openings.insert(quotient_openings.end(), layer.begin() + begin, layer.begin() + end);
        }
    }

    std::vector<u64> trace_openings;
    append_qsp_trace_openings_retained(
        trace_openings,
        trace.d_layer0_saved,
        trace_tree,
        opt.leaf_count,
        opt.committed_columns,
        query_indices
    );

    const double openings_ms = now_ms_host_clock() - openings_t0;

    size_t retained_merkle_tree_bytes =
        (size_t)trace_tree.total_nodes * P2_DIGEST * sizeof(u64);

    for (const DeviceTreeForProof& tree_for_size : fri.retained_trees) {
        retained_merkle_tree_bytes +=
            (size_t)tree_for_size.total_nodes * P2_DIGEST * sizeof(u64);
    }

    const double write_t0 = now_ms_host_clock();
    write_qsp_proof_file(
        opt.proof_out,
        p2,
        scale_log2,
        opt.leaf_count,
        opt.committed_columns,
        opt.final_rows,
        fri.rounds,
        (int)(fri.roots.size() / P2_DIGEST),
        opt.fri_query_count,
        transition_ratio,
        alpha,
        public_digest_vec,
        statement_digest_vec,
        trace_root_vec,
        fri.roots,
        fri.final_matrix,
        quotient_openings,
        trace_openings
    );
    const double write_ms = now_ms_host_clock() - write_t0;
    const double total_ms = now_ms_host_clock() - total_t0;

    const u64* quotient_root = &fri.roots[0];
    const u64* final_root = &fri.roots[(size_t)(fri.roots.size() / P2_DIGEST - 1) * P2_DIGEST];

    std::cout << "QINGMING-STARK-G64 proof builder\n";
    std::cout << "status: PASS\n";
    std::cout << "proof_file: " << opt.proof_out << "\n";
    std::cout << "proof_format: QSPG64\n";
    std::cout << "air_profile: QINGMING-AIR-GEOCLOCK-G64\n";
    std::cout << "scale_log2: " << scale_log2 << "\n";
    std::cout << "layer0_rows: " << opt.leaf_count << "\n";
    std::cout << "trace_columns: " << opt.committed_columns << "\n";
    std::cout << "quotient_columns: " << opt.committed_columns << "\n";
    std::cout << "fri_rounds: " << fri.rounds << "\n";
    std::cout << "fri_root_count: " << (fri.roots.size() / P2_DIGEST) << "\n";
    std::cout << "fri_query_count: " << opt.fri_query_count << "\n";
    std::cout << "ntt_operator: " << (trace.used_fast_xyz ? "fast_prelayout_xyz" : "rowwise_radix2_fallback") << "\n";
    std::cout << "transition_ratio: " << hex64(transition_ratio) << "\n";
    std::cout << "composition_alpha: " << hex64(alpha) << "\n";
    std::cout << "trace_h2d_ms: " << std::fixed << std::setprecision(3) << trace.h2d_ms << "\n";
    std::cout << "trace_ntt_total_ms: " << std::fixed << std::setprecision(3) << trace.ntt.total_ms << "\n";
    std::cout << "trace_merkle_commit_ms: " << std::fixed << std::setprecision(3) << trace_tree.total_ms << "\n";
    std::cout << "quotient_eval_ms: " << std::fixed << std::setprecision(3) << quotient_eval_ms << "\n";
    std::cout << "quotient_snapshot_ms: " << std::fixed << std::setprecision(3) << quotient_snapshot_ms << "\n";
    std::cout << "quotient_fri_total_ms: " << std::fixed << std::setprecision(3) << fri.total_ms << "\n";
    std::cout << "transcript_ms: " << std::fixed << std::setprecision(3) << transcript_ms << "\n";
    std::cout << "opening_source: retained_merkle_trees\n";
    std::cout << "retained_merkle_tree_bytes: " << retained_merkle_tree_bytes << "\n";
    std::cout << "retained_merkle_tree_mib: " << std::fixed << std::setprecision(3)
              << ((double)retained_merkle_tree_bytes / (1024.0 * 1024.0)) << "\n";
    std::cout << "opening_extraction_ms: " << std::fixed << std::setprecision(3) << openings_ms << "\n";
    std::cout << "write_proof_ms: " << std::fixed << std::setprecision(3) << write_ms << "\n";
    std::cout << "proof_total_ms: " << std::fixed << std::setprecision(3) << total_ms << "\n";
    std::cout << "quotient_openings_field_elements: " << quotient_openings.size() << "\n";
    std::cout << "trace_openings_field_elements: " << trace_openings.size() << "\n";
    print_digest("trace_root", trace_tree.root);
    print_digest("quotient_root", quotient_root);
    print_digest("final_root", final_root);

    HIP_CHECK(hipFree(d_work));
    free_retained_fri_trees(fri);
    free_device_tree(trace_tree);
    HIP_CHECK(hipEventDestroy(qe_start));
    HIP_CHECK(hipEventDestroy(qe_stop));
    HIP_CHECK(hipEventDestroy(qs_start));
    HIP_CHECK(hipEventDestroy(qs_stop));
    HIP_CHECK(hipFree(d_quotient_saved));
    HIP_CHECK(hipFree(d_quotient));
    HIP_CHECK(hipFree(trace.d_layer0_saved));
    HIP_CHECK(hipFree(trace.d_layer0));
}


// -----------------------------
// CLI
// -----------------------------

static void usage(const char* argv0) {
    std::cerr << "Usage:\n";
    std::cerr << "  hipcc -O3 -std=c++17 qingming_merkle_g64_final.hip -o qingming_merkle_g64_final\n";
    std::cerr << "  " << argv0 << " qingming_poseidon2_g64_constants.h [options]\n\n";
    std::cerr << "Modes:\n";
    std::cerr << "  --mode check       Merkle correctness + performance on full tree\n";
    std::cerr << "  --mode perf        Merkle root-only performance for one scale\n";
    std::cerr << "  --mode sweep       Merkle root-only performance for scale-min..scale-max\n";
    std::cerr << "  --mode fri-check   FRI CPU/GPU correctness on commit/fold chain\n";
    std::cerr << "  --mode fri-perf    FRI GPU performance on commit/fold chain\n";
    std::cerr << "  --mode fri-sweep   FRI GPU multi-scale sweep\n";
    std::cerr << "  --mode e2e-check   E2E CPU/GPU correctness: NTT FAST + FRI\n";
    std::cerr << "  --mode e2e-perf    E2E GPU performance: H2D + NTT FAST + FRI\n";
    std::cerr << "  --mode e2e-sweep   E2E GPU multi-scale sweep\n";
    std::cerr << "  --mode proof       Build QINGMING-PROOF-G64 v1 proof file\n";
    std::cerr << "  --mode stark-check QINGMING-STARK-G64 correctness baseline\n";
    std::cerr << "  --mode stark-perf  QINGMING-STARK-G64 performance baseline\n";
    std::cerr << "  --mode stark-prove Build QSPG64 full STARK proof file\n\n";
    std::cerr << "Options:\n";
    std::cerr << "  --leaves N         leaf_count, must be power of two. Default: 4096\n";
    std::cerr << "  --cols C           committed_columns. Default: 16\n";
    std::cerr << "  --scale K          total committed elements = 2^K; leaf_count = 2^K / cols\n";
    std::cerr << "  --scale-min K      sweep start. Default: 20\n";
    std::cerr << "  --scale-max K      sweep end. Default: 27\n";
    std::cerr << "  --query I          opening query index. Default: 123\n";
    std::cerr << "  --repeat R         repeat performance and keep best time. Default: 1\n";
    std::cerr << "  --final-rows N     FRI stop rows, power of two. Default: 1\n";
    std::cerr << "  --query-count N    FRI query count. v1 fixed default: 32\n";
    std::cerr << "  --proof-out PATH   proof output path for --mode proof or --mode stark-prove\n";
}

static Options parse_args(int argc, char** argv) {
    if (argc < 2) {
        usage(argv[0]);
        std::exit(2);
    }

    Options opt;
    opt.constants_path = argv[1];

    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];

        auto need_value = [&](const char* name) -> const char* {
            if (i + 1 >= argc) throw std::runtime_error(std::string(name) + " needs value");
            return argv[++i];
        };

        if (a == "--mode") {
            std::string m = need_value("--mode");
            if (m == "check") opt.mode = Mode::Check;
            else if (m == "perf") opt.mode = Mode::Perf;
            else if (m == "sweep") opt.mode = Mode::Sweep;
            else if (m == "fri-check") opt.mode = Mode::FriCheck;
            else if (m == "fri-perf") opt.mode = Mode::FriPerf;
            else if (m == "fri-sweep") opt.mode = Mode::FriSweep;
            else if (m == "e2e-check") opt.mode = Mode::E2ECheck;
            else if (m == "e2e-perf") opt.mode = Mode::E2EPerf;
            else if (m == "e2e-sweep") opt.mode = Mode::E2ESweep;
            else if (m == "proof") opt.mode = Mode::Proof;
            else if (m == "stark-check") opt.mode = Mode::StarkCheck;
            else if (m == "stark-perf") opt.mode = Mode::StarkPerf;
            else if (m == "stark-prove") opt.mode = Mode::StarkProve;
            else throw std::runtime_error("unknown mode: " + m);
        } else if (a == "--leaves") {
            opt.leaf_count = std::stoi(need_value("--leaves"));
        } else if (a == "--cols") {
            opt.committed_columns = std::stoi(need_value("--cols"));
        } else if (a == "--scale") {
            opt.scale_k = std::stoi(need_value("--scale"));
        } else if (a == "--scale-min") {
            opt.scale_min = std::stoi(need_value("--scale-min"));
        } else if (a == "--scale-max") {
            opt.scale_max = std::stoi(need_value("--scale-max"));
        } else if (a == "--query") {
            opt.query_index = std::stoi(need_value("--query"));
        } else if (a == "--repeat") {
            opt.repeat = std::stoi(need_value("--repeat"));
        } else if (a == "--final-rows") {
            opt.final_rows = std::stoi(need_value("--final-rows"));
        } else if (a == "--query-count") {
            opt.fri_query_count = std::stoi(need_value("--query-count"));
        } else if (a == "--proof-out") {
            opt.proof_out = need_value("--proof-out");
        } else {
            throw std::runtime_error("unknown option: " + a);
        }
    }

    if (opt.committed_columns <= 0) throw std::runtime_error("committed_columns must be positive");
    if (opt.repeat <= 0) throw std::runtime_error("repeat must be positive");

    auto apply_scale = [&](int k) {
        if (k < 1 || k > 31) throw std::runtime_error("scale must be in [1,31] for this tool");
        u64 scale_elements = 1ULL << k;

        if (scale_elements % (u64)opt.committed_columns != 0) {
            throw std::runtime_error("2^scale must be divisible by committed_columns");
        }

        u64 leaves = scale_elements / (u64)opt.committed_columns;

        if (leaves > (u64)std::numeric_limits<int>::max()) {
            throw std::runtime_error("leaf_count too large for this tool");
        }

        opt.leaf_count = (int)leaves;
    };

    if ((opt.mode == Mode::Perf ||
         opt.mode == Mode::FriPerf ||
         opt.mode == Mode::FriCheck ||
         opt.mode == Mode::E2EPerf ||
         opt.mode == Mode::E2ECheck ||
         opt.mode == Mode::Proof ||
         opt.mode == Mode::StarkPerf ||
         opt.mode == Mode::StarkCheck ||
         opt.mode == Mode::StarkProve) && opt.scale_k >= 0) {
        apply_scale(opt.scale_k);
    }

    if (opt.mode == Mode::Sweep || opt.mode == Mode::FriSweep || opt.mode == Mode::E2ESweep) {
        if (opt.scale_min < 1 || opt.scale_max > 31 || opt.scale_min > opt.scale_max) {
            throw std::runtime_error("bad sweep range");
        }
    }

    if (opt.mode != Mode::Sweep && opt.mode != Mode::FriSweep && opt.mode != Mode::E2ESweep) {
        if (opt.leaf_count <= 0) throw std::runtime_error("leaf_count must be positive");
        if (!is_power_of_two_u64((u64)opt.leaf_count)) {
            throw std::runtime_error("leaf_count must be power of two");
        }

        opt.query_index %= opt.leaf_count;
        if (opt.query_index < 0) opt.query_index += opt.leaf_count;
    }

    if (opt.final_rows <= 0 || !is_power_of_two_u64((u64)opt.final_rows)) {
        throw std::runtime_error("final_rows must be a positive power of two");
    }

    if (opt.fri_query_count != 32) {
        throw std::runtime_error("QINGMING-PROOF-G64 v1 fixes fri_query_count = 32");
    }

    if (opt.mode != Mode::Sweep && opt.mode != Mode::FriSweep && opt.mode != Mode::E2ESweep) {
        if (opt.final_rows > opt.leaf_count) throw std::runtime_error("final_rows cannot exceed leaf_count");
        if (((u64)opt.leaf_count % (u64)opt.final_rows) != 0) {
            throw std::runtime_error("leaf_count must be divisible by final_rows");
        }
    }

    return opt;
}

static GpuMerkleResult best_root_run(const std::vector<u64>& matrix, int leaves, int cols, int repeat) {
    GpuMerkleResult best;
    bool have = false;

    for (int r = 0; r < repeat; ++r) {
        GpuMerkleResult cur = gpu_build_root_only(matrix, leaves, cols);
        if (!have || cur.total_ms < best.total_ms) {
            best = std::move(cur);
            have = true;
        }
    }

    return best;
}

int main(int argc, char** argv) {
    try {
        Options opt = parse_args(argc, argv);

        FrozenPoseidon2 p2 = load_poseidon2_constants(opt.constants_path);

        if (fingerprint_poseidon2_params(p2) != p2.params_fingerprint) {
            throw std::runtime_error("Poseidon2 params fingerprint mismatch");
        }

        upload_poseidon2_constants(p2);

        if (opt.mode == Mode::Check) {
            std::vector<u64> matrix = make_committed_matrix(opt.leaf_count, opt.committed_columns);
            check_canonical_matrix(matrix);

            GpuMerkleResult gpu = gpu_build_full_tree(matrix, opt.leaf_count, opt.committed_columns);
            run_correctness(matrix, gpu, opt.leaf_count, opt.committed_columns, opt.query_index, p2);

            report_full("QINGMING-MERKLE-G64 correctness/performance", p2, opt, gpu, true);
            return 0;
        }

        if (opt.mode == Mode::Perf) {
            std::vector<u64> matrix = make_committed_matrix(opt.leaf_count, opt.committed_columns);
            check_canonical_matrix(matrix);

            GpuMerkleResult gpu = best_root_run(matrix, opt.leaf_count, opt.committed_columns, opt.repeat);

            report_full("QINGMING-MERKLE-G64 performance", p2, opt, gpu, false);
            return 0;
        }

        if (opt.mode == Mode::Sweep) {
            std::cout << "QINGMING-MERKLE-G64 multi-scale performance sweep\n";
            std::cout << "status: PASS\n";
            std::cout << "operator: generic-layered-final\n";
            std::cout << "hash: QINGMING-POSEIDON2-G64\n";
            std::cout << "poseidon2_params_fingerprint: " << hex64(p2.params_fingerprint) << "\n";
            std::cout << "cols: " << opt.committed_columns << "\n";
            std::cout << "repeat_best_of: " << opt.repeat << "\n";
            std::cout << "csv_header: scale_k,leaf_count,cols,committed_elements,tree_height,gpu_total_ms,gpu_leaf_ms,gpu_reduce_ms,poseidon2_total_permutations,poseidon2_permutations_per_sec,committed_elements_per_sec,root\n";

            for (int k = opt.scale_min; k <= opt.scale_max; ++k) {
                const u64 scale_elements = 1ULL << k;

                if (scale_elements % (u64)opt.committed_columns != 0) continue;

                const u64 leaves_u64 = scale_elements / (u64)opt.committed_columns;
                if (leaves_u64 == 0 || leaves_u64 > (u64)std::numeric_limits<int>::max()) continue;

                const int leaves = (int)leaves_u64;
                if (!is_power_of_two_u64((u64)leaves)) continue;

                std::vector<u64> matrix = make_committed_matrix(leaves, opt.committed_columns);
                check_canonical_matrix(matrix);

                GpuMerkleResult gpu = best_root_run(matrix, leaves, opt.committed_columns, opt.repeat);
                report_sweep_row(k, leaves, opt.committed_columns, gpu);
            }

            return 0;
        }

        if (opt.mode == Mode::FriCheck) {
            std::vector<u64> matrix = make_committed_matrix(opt.leaf_count, opt.committed_columns);
            check_canonical_matrix(matrix);

            GpuFriResult fri = gpu_fri_chain(
                matrix,
                opt.leaf_count,
                opt.committed_columns,
                opt.final_rows,
                p2,
                true
            );

            run_fri_correctness(matrix, opt.leaf_count, opt.committed_columns, opt.final_rows, p2, fri);
            report_fri("QINGMING-FRI-G64 correctness/performance", p2, opt, fri, true);
            return 0;
        }

        if (opt.mode == Mode::FriPerf) {
            std::vector<u64> matrix = make_committed_matrix(opt.leaf_count, opt.committed_columns);
            check_canonical_matrix(matrix);

            GpuFriResult best;
            bool have = false;

            for (int r = 0; r < opt.repeat; ++r) {
                GpuFriResult cur = gpu_fri_chain(
                    matrix,
                    opt.leaf_count,
                    opt.committed_columns,
                    opt.final_rows,
                    p2,
                    false
                );

                if (!have || cur.total_ms < best.total_ms) {
                    best = std::move(cur);
                    have = true;
                }
            }

            report_fri("QINGMING-FRI-G64 performance", p2, opt, best, false);
            return 0;
        }

        if (opt.mode == Mode::FriSweep) {
            std::cout << "QINGMING-FRI-G64 multi-scale performance sweep\n";
            std::cout << "status: PASS\n";
            std::cout << "operator: fri-g64-commit-fold-generic-layered-merkle\n";
            std::cout << "hash: QINGMING-POSEIDON2-G64\n";
            std::cout << "merkle_operator: generic-layered-final\n";
            std::cout << "poseidon2_params_fingerprint: " << hex64(p2.params_fingerprint) << "\n";
            std::cout << "cols: " << opt.committed_columns << "\n";
            std::cout << "final_rows: " << opt.final_rows << "\n";
            std::cout << "repeat_best_of: " << opt.repeat << "\n";
            std::cout << "csv_header: scale_k,layer0_rows,cols,committed_elements_layer0,final_rows,fri_rounds,fri_root_count,gpu_total_ms,gpu_merkle_ms,gpu_fold_ms,final_root\n";

            for (int k = opt.scale_min; k <= opt.scale_max; ++k) {
                const u64 scale_elements = 1ULL << k;
                if (scale_elements % (u64)opt.committed_columns != 0) continue;

                const u64 leaves_u64 = scale_elements / (u64)opt.committed_columns;
                if (leaves_u64 == 0 || leaves_u64 > (u64)std::numeric_limits<int>::max()) continue;

                const int leaves = (int)leaves_u64;
                if (!is_power_of_two_u64((u64)leaves)) continue;
                if (opt.final_rows > leaves || (leaves % opt.final_rows) != 0) continue;

                std::vector<u64> matrix = make_committed_matrix(leaves, opt.committed_columns);
                check_canonical_matrix(matrix);

                GpuFriResult best;
                bool have = false;

                for (int r = 0; r < opt.repeat; ++r) {
                    GpuFriResult cur = gpu_fri_chain(
                        matrix,
                        leaves,
                        opt.committed_columns,
                        opt.final_rows,
                        p2,
                        false
                    );

                    if (!have || cur.total_ms < best.total_ms) {
                        best = std::move(cur);
                        have = true;
                    }
                }

                report_fri_sweep_row(k, leaves, opt.committed_columns, opt.final_rows, best);
            }

            return 0;
        }

        if (opt.mode == Mode::E2ECheck) {
            std::vector<u64> raw_matrix = make_committed_matrix(opt.leaf_count, opt.committed_columns);
            check_canonical_matrix(raw_matrix);

            GpuE2EResult e2e = gpu_e2e_ntt_fri(
                raw_matrix,
                opt.leaf_count,
                opt.committed_columns,
                opt.final_rows,
                true
            );

            run_e2e_correctness(
                raw_matrix,
                opt.leaf_count,
                opt.committed_columns,
                opt.final_rows,
                p2,
                e2e
            );

            report_e2e("QINGMING-ZKP E2E correctness/performance", p2, opt, e2e, true);
            return 0;
        }

        if (opt.mode == Mode::E2EPerf) {
            std::vector<u64> raw_matrix = make_committed_matrix(opt.leaf_count, opt.committed_columns);
            check_canonical_matrix(raw_matrix);

            GpuE2EResult best;
            bool have = false;

            for (int r = 0; r < opt.repeat; ++r) {
                GpuE2EResult cur = gpu_e2e_ntt_fri(
                    raw_matrix,
                    opt.leaf_count,
                    opt.committed_columns,
                    opt.final_rows,
                    false
                );

                if (!have || cur.gpu_pipeline_ms < best.gpu_pipeline_ms) {
                    best = std::move(cur);
                    have = true;
                }
            }

            report_e2e("QINGMING-ZKP E2E performance", p2, opt, best, false);
            return 0;
        }

        if (opt.mode == Mode::E2ESweep) {
            std::cout << "QINGMING-ZKP E2E multi-scale performance sweep\n";
            std::cout << "status: PASS\n";
            std::cout << "operator: qingming-g64-ntt-fast-plus-fri-g64\n";
            std::cout << "hash: QINGMING-POSEIDON2-G64\n";
            std::cout << "merkle_operator: generic-layered-final\n";
            std::cout << "poseidon2_params_fingerprint: " << hex64(p2.params_fingerprint) << "\n";
            std::cout << "cols: " << opt.committed_columns << "\n";
            std::cout << "final_rows: " << opt.final_rows << "\n";
            std::cout << "repeat_best_of: " << opt.repeat << "\n";
            std::cout << "csv_header: scale_k,layer0_rows,cols,committed_elements_layer0,final_rows,fri_rounds,h2d_input_ms,gpu_ntt_total_ms,gpu_fri_total_ms,gpu_pipeline_ms,e2e_ms,final_root\n";

            for (int k = opt.scale_min; k <= opt.scale_max; ++k) {
                const u64 scale_elements = 1ULL << k;
                if (scale_elements % (u64)opt.committed_columns != 0) continue;

                const u64 leaves_u64 = scale_elements / (u64)opt.committed_columns;
                if (leaves_u64 == 0 || leaves_u64 > (u64)std::numeric_limits<int>::max()) continue;

                const int leaves = (int)leaves_u64;
                if (!is_power_of_two_u64((u64)leaves)) continue;
                if (opt.final_rows > leaves || (leaves % opt.final_rows) != 0) continue;

                std::vector<u64> raw_matrix = make_committed_matrix(leaves, opt.committed_columns);
                check_canonical_matrix(raw_matrix);

                GpuE2EResult best;
                bool have = false;

                for (int r = 0; r < opt.repeat; ++r) {
                    GpuE2EResult cur = gpu_e2e_ntt_fri(
                        raw_matrix,
                        leaves,
                        opt.committed_columns,
                        opt.final_rows,
                        false
                    );

                    if (!have || cur.gpu_pipeline_ms < best.gpu_pipeline_ms) {
                        best = std::move(cur);
                        have = true;
                    }
                }

                report_e2e_sweep_row(k, leaves, opt.committed_columns, opt.final_rows, best);
            }

            return 0;
        }

        if (opt.mode == Mode::Proof) {
            build_qingming_proof_g64(opt, p2);
            return 0;
        }

        if (opt.mode == Mode::StarkCheck) {
            StarkRunResult stark = run_qingming_stark_g64_v1(opt, p2, true);
            report_qingming_stark_g64_v1(
                "QINGMING-STARK-G64 correctness/performance",
                opt,
                p2,
                stark,
                true
            );
            return 0;
        }

        if (opt.mode == Mode::StarkPerf) {
            StarkRunResult stark = run_qingming_stark_g64_v1(opt, p2, false);
            report_qingming_stark_g64_v1(
                "QINGMING-STARK-G64 performance",
                opt,
                p2,
                stark,
                false
            );
            return 0;
        }

        if (opt.mode == Mode::StarkProve) {
            build_qingming_stark_proof_g64(opt, p2);
            return 0;
        }

        throw std::runtime_error("unreachable mode");

    } catch (const std::exception& e) {
        std::cerr << "status: FAIL\n";
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
#undef main

#include <filesystem>
#include <numeric>

namespace qmgpu {

static constexpr int CANON_COLS = 64;
static constexpr int CANON_BLOWUP = 8;
static constexpr int CANON_QUERIES = 64;
static constexpr int CANON_TERMINAL = 16;

struct Dp2 { u64 a, b; };

__host__ __device__ __forceinline__ u64 d_pow(u64 x, u64 e) {
    u64 r = 1;
    while (e) {
        if (e & 1) r = g64_mul(r, x);
        x = g64_mul(x, x);
        e >>= 1;
    }
    return r;
}
__host__ __device__ __forceinline__ u64 d_inv(u64 x) { return d_pow(x, G64_P - 2); }
__host__ __device__ __forceinline__ Dp2 e_add(Dp2 x, Dp2 y) {
    return {g64_add(x.a,y.a), g64_add(x.b,y.b)};
}
__host__ __device__ __forceinline__ Dp2 e_sub(Dp2 x, Dp2 y) {
    return {g64_sub(x.a,y.a), g64_sub(x.b,y.b)};
}
__host__ __device__ __forceinline__ Dp2 e_mul(Dp2 x, Dp2 y) {
    return {
        g64_add(g64_mul(x.a,y.a), g64_mul(7, g64_mul(x.b,y.b))),
        g64_add(g64_mul(x.a,y.b), g64_mul(x.b,y.a))
    };
}
__host__ __device__ __forceinline__ Dp2 e_mul_base(Dp2 x, u64 y) {
    return {g64_mul(x.a,y), g64_mul(x.b,y)};
}

struct DeviceBuf {
    u64* p = nullptr;
    size_t words = 0;
    DeviceBuf() = default;
    explicit DeviceBuf(size_t n): words(n) {
        if (n) HIP_CHECK(hipMalloc(&p, n * sizeof(u64)));
    }
    DeviceBuf(const DeviceBuf&) = delete;
    DeviceBuf& operator=(const DeviceBuf&) = delete;
    DeviceBuf(DeviceBuf&& o) noexcept: p(o.p), words(o.words) { o.p=nullptr; o.words=0; }
    DeviceBuf& operator=(DeviceBuf&& o) noexcept {
        if (this != &o) { if (p) (void)hipFree(p); p=o.p; words=o.words; o.p=nullptr; o.words=0; }
        return *this;
    }
    ~DeviceBuf(){ if(p) (void)hipFree(p); }
};

struct GpuTimer {
    hipEvent_t a{}, b{};
    GpuTimer(){ HIP_CHECK(hipEventCreate(&a)); HIP_CHECK(hipEventCreate(&b)); }
    ~GpuTimer(){ (void)hipEventDestroy(a); (void)hipEventDestroy(b); }
    void start(){ HIP_CHECK(hipEventRecord(a)); }
    float stop(){ HIP_CHECK(hipEventRecord(b)); HIP_CHECK(hipEventSynchronize(b)); return event_ms(a,b); }
};

static double host_ms_now(){
    using C=std::chrono::steady_clock;
    static const auto zero=C::now();
    return std::chrono::duration<double,std::milli>(C::now()-zero).count();
}

__global__ void generate_trace_kernel(u64* trace, int rows, const u64* initial) {
    if (blockIdx.x || threadIdx.x) return;
    for (int j=0;j<16;++j) {
        const u64 x=initial[j];
        trace[j]=x;
        trace[16+j]=0;
        trace[32+j]=g64_mul(x, initial[(j+1)&15]);
        trace[48+j]=g64_mul(x,x);
    }
    for (int r=1;r<rows;++r) {
        const u64* c=trace+(size_t)(r-1)*CANON_COLS;
        u64* n=trace+(size_t)r*CANON_COLS;
        for (int j=0;j<16;++j) {
            const u64 x=c[j], y=c[(j+1)&15], m=c[32+j], h=c[48+j];
            u64 lane = g64_add(0x9e3779b97f4a7c15ULL, (u64)j);
            u64 v = g64_add(lane, x);
            v = g64_add(v, g64_mul(3,y));
            v = g64_add(v, g64_mul(5,h));
            v = g64_add(v, g64_mul(7,m));
            n[j]=v;
            n[16+j]=g64_add(c[16+j],m);
        }
        for (int j=0;j<16;++j) {
            n[32+j]=g64_mul(n[j],n[(j+1)&15]);
            n[48+j]=g64_mul(n[j],n[j]);
        }
    }
}

__global__ void ntt_scale_kernel(u64* matrix, int rows, int cols, u64 scale) {
    const int i=blockIdx.x*blockDim.x+threadIdx.x;
    const int total=rows*cols;
    if(i<total) matrix[i]=g64_mul(matrix[i],scale);
}

__global__ void make_shift_powers_kernel(u64* powers, int n, u64 shift) {
    const int i=blockIdx.x*blockDim.x+threadIdx.x;
    if(i<n) powers[i]=d_pow(shift,(u64)i);
}

__global__ void coset_pad_kernel(const u64* coeffs, u64* out, const u64* powers,
                                 int n, int m, int cols) {
    const int i=blockIdx.x*blockDim.x+threadIdx.x;
    const int total=m*cols;
    if(i>=total) return;
    const int r=i/cols, c=i-r*cols;
    out[i]=(r<n)?g64_mul(coeffs[(size_t)r*cols+c],powers[r]):0;
}

static std::vector<u64> make_twiddles_general(int rows, bool inverse) {
    check_ntt_root_contract(rows);
    std::vector<u64> tw;
    tw.reserve((size_t)rows-1);
    u64 root=g64_pow_u64(G64_ROOT_2_32,(1ULL<<32)/(u64)rows);
    if(inverse) root=g64_pow_u64(root,G64_P-2);
    for(int len=2;len<=rows;len<<=1){
        int half=len>>1;
        u64 wlen=g64_pow_u64(root,(u64)rows/(u64)len), w=1;
        for(int j=0;j<half;++j){tw.push_back(w);w=g64_mul(w,wlen);}
    }
    return tw;
}

static GpuNttResult gpu_ntt_general(u64* d, int rows, int cols, bool inverse, double* h2d_ms=nullptr) {
    GpuNttResult result;
    auto tw=make_twiddles_general(rows,inverse);
    DeviceBuf d_tw(tw.size());
    double hcopy=host_ms_now();
    HIP_CHECK(hipMemcpy(d_tw.p,tw.data(),tw.size()*8,hipMemcpyHostToDevice));
    if(h2d_ms)*h2d_ms+=host_ms_now()-hcopy;
    GpuTimer total, stage;
    const int threads=256;
    total.start();
    int all=rows*cols;
    stage.start();
    ntt_bit_reverse_rows_kernel<<<(all+threads-1)/threads,threads>>>(d,rows,cols,log2_u64(rows));
    HIP_CHECK(hipGetLastError());
    result.bit_reverse_ms=stage.stop();
    int off=0;
    for(int len=2;len<=rows;len<<=1){
        int work=(rows>>1)*cols;
        stage.start();
        ntt_stage_rows_kernel<<<(work+threads-1)/threads,threads>>>(d,d_tw.p,rows,cols,len,off);
        HIP_CHECK(hipGetLastError());
        float ms=stage.stop();
        result.stage_ms.push_back(ms); result.stages_ms+=ms; off+=(len>>1);
    }
    if(inverse){
        u64 ni=g64_pow_u64((u64)rows,G64_P-2);
        stage.start();
        ntt_scale_kernel<<<(all+threads-1)/threads,threads>>>(d,rows,cols,ni);
        HIP_CHECK(hipGetLastError());
        float ms=stage.stop(); result.stage_ms.push_back(ms); result.stages_ms+=ms;
    }
    result.total_ms=total.stop();
    return result;
}

__device__ __forceinline__ void canonical_hash_absorb_value(u64 state[P2_T], int& pos, u64 x) {
    state[pos]=g64_add(state[pos],x);
    ++pos;
    if(pos==P2_RATE){gpu_poseidon2_perm(state);pos=0;}
}

__device__ __forceinline__ void canonical_hash_finish(u64 state[P2_T], int pos, u64 out[P2_DIGEST]) {
    if(pos!=0) state[pos]=g64_add(state[pos],1);
    gpu_poseidon2_perm(state);
    #pragma unroll
    for(int i=0;i<P2_DIGEST;++i) out[i]=state[i];
}

__device__ __forceinline__ void canonical_indexed_leaf(const u64* vals, int cols, u64 idx,
                                                        u64 out[P2_DIGEST]) {
    u64 state[P2_T]={};
    state[P2_RATE]=d_p2_domains[DOMAIN_MERKLE_LEAF];
    int pos=0;
    canonical_hash_absorb_value(state,pos,idx);
    for(int i=0;i<cols;++i) canonical_hash_absorb_value(state,pos,vals[i]);
    canonical_hash_finish(state,pos,out);
}

__global__ void canonical_leaf_kernel(const u64* matrix,u64* leaves,int rows,int cols){
    int idx=blockIdx.x*blockDim.x+threadIdx.x;
    if(idx>=rows)return;
    u64 d[P2_DIGEST]; canonical_indexed_leaf(matrix+(size_t)idx*cols,cols,(u64)idx,d);
    for(int i=0;i<P2_DIGEST;++i)leaves[(size_t)idx*P2_DIGEST+i]=d[i];
}

struct DTree {
    DeviceBuf storage;
    int leaves=0;
    float leaf_ms=0, reduce_ms=0, total_ms=0;
    DTree()=default;
    DTree(DTree&&)=default;
    DTree& operator=(DTree&&)=default;
};

static DTree build_canonical_tree(const u64* d_matrix,int rows,int cols){
    DTree t; t.leaves=rows; t.storage=DeviceBuf((size_t)(2*rows-1)*P2_DIGEST);
    GpuTimer total, stage; total.start();
    int threads=256;
    stage.start();
    canonical_leaf_kernel<<<(rows+threads-1)/threads,threads>>>(d_matrix,t.storage.p,rows,cols);
    HIP_CHECK(hipGetLastError()); t.leaf_ms=stage.stop();
    int nodes=rows; size_t cur=0, next=rows;
    while(nodes>1){
        int out=nodes/2;
        stage.start();
        merkle_reduce_kernel<<<(out+threads-1)/threads,threads>>>(t.storage.p+cur*P2_DIGEST,
            t.storage.p+next*P2_DIGEST,out);
        HIP_CHECK(hipGetLastError()); t.reduce_ms+=stage.stop();
        cur=next; next+=out; nodes=out;
    }
    t.total_ms=total.stop(); return t;
}

static std::array<u64,4> tree_root(const DTree& t){
    std::array<u64,4> r{};
    HIP_CHECK(hipMemcpy(r.data(),t.storage.p+(size_t)(2*t.leaves-2)*4,32,hipMemcpyDeviceToHost));
    return r;
}

__device__ __forceinline__ void composition_add(Dp2& acc,Dp2& power,Dp2 alpha,u64 value,u64 invz){
    acc=e_add(acc,e_mul(power,Dp2{g64_mul(value,invz),0}));
    power=e_mul(power,alpha);
}

__global__ void composition_kernel(const u64* lde,Dp2* q,int rows,const u64* pub_init,
                                   const u64* pub_final,u64 alpha_a,u64 alpha_b,
                                   u64 omega_m,u64 omega_n_inv,u64 trace_n){
    int i=blockIdx.x*blockDim.x+threadIdx.x;
    if(i>=rows)return;
    const u64* c=lde+(size_t)i*CANON_COLS;
    const u64* n=lde+(size_t)((i+CANON_BLOWUP)%rows)*CANON_COLS;
    u64 z=g64_mul(7,d_pow(omega_m,(u64)i));
    u64 zn=d_pow(z,trace_n);
    u64 ztrans=g64_mul(g64_sub(zn,1),d_inv(g64_sub(z,omega_n_inv)));
    u64 inv_trans=d_inv(ztrans), inv_init=d_inv(g64_sub(z,1)), inv_final=d_inv(g64_sub(z,omega_n_inv));
    Dp2 alpha{alpha_a,alpha_b}, power{1,0}, acc{0,0};
    for(int j=0;j<16;++j){
        u64 x=c[j],y=c[(j+1)&15],m=c[32+j],h=c[48+j];
        composition_add(acc,power,alpha,g64_sub(m,g64_mul(x,y)),inv_trans);
        composition_add(acc,power,alpha,g64_sub(h,g64_mul(x,x)),inv_trans);
        composition_add(acc,power,alpha,g64_sub(g64_sub(n[16+j],c[16+j]),m),inv_trans);
        u64 lane=g64_add(0x9e3779b97f4a7c15ULL,(u64)j);
        u64 rhs=g64_add(lane,x); rhs=g64_add(rhs,g64_mul(3,y));
        rhs=g64_add(rhs,g64_mul(5,h)); rhs=g64_add(rhs,g64_mul(7,m));
        composition_add(acc,power,alpha,g64_sub(n[j],rhs),inv_trans);
    }
    for(int j=0;j<16;++j)composition_add(acc,power,alpha,g64_sub(c[j],pub_init[j]),inv_init);
    for(int j=0;j<16;++j)composition_add(acc,power,alpha,c[16+j],inv_init);
    for(int j=0;j<16;++j)composition_add(acc,power,alpha,g64_sub(c[16+j],pub_final[j]),inv_final);
    q[i]=acc;
}

__global__ void fri_fold_canonical_kernel(const Dp2* cur,Dp2* next,int half,
                                           u64 beta_a,u64 beta_b,u64 offset,u64 omega){
    int i=blockIdx.x*blockDim.x+threadIdx.x;
    if(i>=half)return;
    Dp2 a=cur[i],b=cur[i+half],beta{beta_a,beta_b};
    u64 inv2=d_inv(2),x=g64_mul(offset,d_pow(omega,(u64)i));
    Dp2 even=e_mul_base(e_add(a,b),inv2);
    Dp2 odd=e_mul_base(e_sub(a,b),g64_mul(inv2,d_inv(x)));
    next[i]=e_add(even,e_mul(beta,odd));
}

static qm::Digest to_digest(const std::array<u64,4>& x){
    qm::Digest d{};for(int i=0;i<4;++i)d[i]=qm::F(x[i]);return d;
}
static std::string digest_text(const std::array<u64,4>& x){
    std::ostringstream s;
    for(int i=0;i<4;++i){if(i)s<<";";s<<"0x"<<std::hex<<std::setw(16)<<std::setfill('0')<<x[i];}
    return s.str();
}

static size_t tree_path_words(int height){return (size_t)height*4;}
static size_t fri_layer_words(int height){return 4+2*tree_path_words(height);}
static size_t opening_words_per_query(int height,int layers){
    size_t w=64+tree_path_words(height)+64+tree_path_words(height);
    for(int l=0;l<layers;++l)w+=fri_layer_words(height-l);
    return w;
}

__global__ void extract_trace_openings_kernel(const u64* lde,const u64* tree,const u64* queries,
                                               u64* out,int rows,int height,size_t stride){
    int q=blockIdx.x;
    if(q>=CANON_QUERIES)return;
    int tid=threadIdx.x;
    u64 idx=queries[q], nxt=(idx+CANON_BLOWUP)%rows;
    size_t base=(size_t)q*stride;
    for(int j=tid;j<64;j+=blockDim.x){out[base+j]=lde[idx*64+j];out[base+64+height*4+j]=lde[nxt*64+j];}
    if(tid==0){
        size_t off=0;int nodes=rows;u64 a=idx,b=nxt;
        size_t p0=base+64,p1=base+64+height*4+64;
        for(int l=0;l<height;++l){
            size_t sa=off+(a^1),sb=off+(b^1);
            for(int k=0;k<4;++k){out[p0+l*4+k]=tree[sa*4+k];out[p1+l*4+k]=tree[sb*4+k];}
            off+=nodes;nodes>>=1;a>>=1;b>>=1;
        }
    }
}

__global__ void extract_fri_openings_kernel(const Dp2* vals,const u64* tree,const u64* queries,
                                             u64* out,int rows,int height,size_t stride,size_t layer_off){
    int q=blockIdx.x;
    if(q>=CANON_QUERIES||threadIdx.x)return;
    u64 idx=queries[q],half=rows/2,base_idx=idx%half;
    size_t dst=(size_t)q*stride+layer_off;
    Dp2 lo=vals[base_idx],hi=vals[base_idx+half];
    out[dst+0]=lo.a;out[dst+1]=lo.b;out[dst+2]=hi.a;out[dst+3]=hi.b;
    size_t off=0,p0=dst+4,p1=p0+(size_t)height*4;int nodes=rows;u64 a=base_idx,b=base_idx+half;
    for(int l=0;l<height;++l){
        size_t sa=off+(a^1),sb=off+(b^1);
        for(int k=0;k<4;++k){out[p0+l*4+k]=tree[sa*4+k];out[p1+l*4+k]=tree[sb*4+k];}
        off+=nodes;nodes>>=1;a>>=1;b>>=1;
    }
}

struct Timings {
    double witness_io_ms=0,h2d_ms=0,gpu_trace_ms=0,gpu_inv_ntt_ms=0,gpu_coset_ms=0,
           gpu_fwd_ntt_ms=0,gpu_trace_merkle_ms=0,gpu_composition_ms=0,
           gpu_fri_merkle_ms=0,gpu_fri_fold_ms=0,gpu_openings_ms=0,d2h_compact_ms=0,
           serialization_ms=0,verification_ms=0,file_io_ms=0,total_ms=0;
};

struct OptionsFinal {
    int scale=20;
    int repeat=1;
    uint64_t seed=7;
    std::string constants="rx7900xtx-24g/qingming_poseidon2_g64_constants.h";
    std::string proof_out="gpu-scale-20.qmg64p01";
    std::string report_out;
    std::string witness;
    std::string trace_in;
    bool no_write=false;
};

static OptionsFinal parse(int argc,char**argv){
    OptionsFinal o;
    for(int i=1;i<argc;++i){
        std::string a=argv[i];auto need=[&](){if(i+1>=argc)throw std::runtime_error("missing value for "+a);return std::string(argv[++i]);};
        if(a=="--scale")o.scale=std::stoi(need());
        else if(a=="--repeat")o.repeat=std::stoi(need());
        else if(a=="--seed")o.seed=std::stoull(need());
        else if(a=="--constants")o.constants=need();
        else if(a=="--proof-out")o.proof_out=need();
        else if(a=="--report-out")o.report_out=need();
        else if(a=="--witness")o.witness=need();
        else if(a=="--trace-in")o.trace_in=need();
        else if(a=="--no-write")o.no_write=true;
        else if(a=="--help"){
            std::cout<<"--scale 20..27 --repeat N --seed N --witness FILE --trace-in FILE --constants FILE --proof-out FILE --report-out FILE --no-write\n";
            std::exit(0);
        }else throw std::runtime_error("unknown option: "+a);
    }
    if(o.scale<20||o.scale>27)throw std::runtime_error("Scale must be 20..27");
    if(o.repeat<1)throw std::runtime_error("repeat must be >=1");
    if(!o.witness.empty()&&!o.trace_in.empty())throw std::runtime_error("--witness and --trace-in are mutually exclusive");
    return o;
}

static std::array<u64,16> load_initial(const OptionsFinal&o,Timings&t){
    double a=host_ms_now();std::array<u64,16>x{};
    if(o.witness.empty()){
        for(int i=0;i<16;++i)x[i]=qm::F(o.seed+17*(uint64_t)i+1).v;
    }else{
        std::ifstream in(o.witness,std::ios::binary);if(!in)throw std::runtime_error("cannot open witness");
        char magic[8];in.read(magic,8);if(in.gcount()!=8||std::string(magic,8)!="QMW64I01")throw std::runtime_error("bad witness magic");
        for(auto&v:x){in.read((char*)&v,8);if(!in||v>=G64_P)throw std::runtime_error("bad witness field");}
        char extra;if(in.read(&extra,1))throw std::runtime_error("trailing witness bytes");
    }
    t.witness_io_ms+=host_ms_now()-a;return x;
}

static uint32_t read_le32(std::istream& in){
    unsigned char b[4];in.read((char*)b,4);if(!in)throw std::runtime_error("truncated trace header");
    return uint32_t(b[0])|(uint32_t(b[1])<<8)|(uint32_t(b[2])<<16)|(uint32_t(b[3])<<24);
}
static uint64_t read_le64(std::istream& in){
    unsigned char b[8];in.read((char*)b,8);if(!in)throw std::runtime_error("truncated trace header");
    uint64_t x=0;for(int i=0;i<8;++i)x|=uint64_t(b[i])<<(8*i);return x;
}

static void upload_trace_file(const OptionsFinal&o,u64* d_trace,int rows,Timings&t,
                              std::array<u64,16>&initial,std::array<u64,16>&final_acc){
    double io_start=host_ms_now();
    std::ifstream in(o.trace_in,std::ios::binary);if(!in)throw std::runtime_error("cannot open trace input");
    char magic[8];in.read(magic,8);
    if(in.gcount()!=8||std::string(magic,8)!="QMT64T01")throw std::runtime_error("bad trace magic");
    uint32_t revision=read_le32(in),scale=read_le32(in);uint64_t file_rows=read_le64(in);
    uint32_t cols=read_le32(in),reserved=read_le32(in);
    if(revision!=1||scale!=(uint32_t)o.scale||file_rows!=(uint64_t)rows||cols!=64||reserved!=0)
        throw std::runtime_error("trace header contract mismatch");
    t.witness_io_ms+=host_ms_now()-io_start;
    const size_t chunk_rows=4096;
    std::vector<u64> buf(chunk_rows*64);
    size_t done=0;
    while(done<(size_t)rows){
        size_t take=std::min(chunk_rows,(size_t)rows-done),words=take*64;
        io_start=host_ms_now();in.read((char*)buf.data(),(std::streamsize)(words*8));
        if((size_t)in.gcount()!=words*8)throw std::runtime_error("truncated trace payload");
        for(size_t i=0;i<words;++i)if(buf[i]>=G64_P)throw std::runtime_error("non-canonical trace field");
        t.witness_io_ms+=host_ms_now()-io_start;
        double h=host_ms_now();HIP_CHECK(hipMemcpy(d_trace+done*64,buf.data(),words*8,hipMemcpyHostToDevice));t.h2d_ms+=host_ms_now()-h;
        done+=take;
    }
    char extra;io_start=host_ms_now();if(in.read(&extra,1))throw std::runtime_error("trailing trace bytes");t.witness_io_ms+=host_ms_now()-io_start;
    double h=host_ms_now();
    HIP_CHECK(hipMemcpy(initial.data(),d_trace,16*8,hipMemcpyDeviceToHost));
    HIP_CHECK(hipMemcpy(final_acc.data(),d_trace+(size_t)(rows-1)*64+16,16*8,hipMemcpyDeviceToHost));
    t.d2h_compact_ms+=host_ms_now()-h;
}

struct LayerRetained { DeviceBuf values; DTree tree; int rows=0; };

static qm::Proof run_once(const OptionsFinal&o,Timings&t,std::array<u64,4>&trace_root_out){
    double total_start=host_ms_now();
    const int trace_log=o.scale-9, lde_log=o.scale-6;
    const int n=1<<trace_log, m=1<<lde_log, height=lde_log, layers=lde_log-4;
    std::array<u64,16> initial{},final_acc{};
    DeviceBuf d_init(16),d_final(16),d_trace((size_t)n*64);
    GpuTimer gt;double h=0;
    if(o.trace_in.empty()){
        initial=load_initial(o,t);
        h=host_ms_now();HIP_CHECK(hipMemcpy(d_init.p,initial.data(),128,hipMemcpyHostToDevice));t.h2d_ms+=host_ms_now()-h;
        gt.start();generate_trace_kernel<<<1,1>>>(d_trace.p,n,d_init.p);HIP_CHECK(hipGetLastError());t.gpu_trace_ms+=gt.stop();
        h=host_ms_now();HIP_CHECK(hipMemcpy(final_acc.data(),d_trace.p+(size_t)(n-1)*64+16,128,hipMemcpyDeviceToHost));t.d2h_compact_ms+=host_ms_now()-h;
    }else{
        upload_trace_file(o,d_trace.p,n,t,initial,final_acc);
        h=host_ms_now();HIP_CHECK(hipMemcpy(d_init.p,initial.data(),128,hipMemcpyHostToDevice));t.h2d_ms+=host_ms_now()-h;
    }
    h=host_ms_now();HIP_CHECK(hipMemcpy(d_final.p,final_acc.data(),128,hipMemcpyHostToDevice));t.h2d_ms+=host_ms_now()-h;

    auto inv=gpu_ntt_general(d_trace.p,n,64,true,&t.h2d_ms);t.gpu_inv_ntt_ms+=inv.total_ms;
    DeviceBuf d_powers(n),d_lde((size_t)m*64);
    gt.start();make_shift_powers_kernel<<<(n+255)/256,256>>>(d_powers.p,n,7);HIP_CHECK(hipGetLastError());
    coset_pad_kernel<<<((size_t)m*64+255)/256,256>>>(d_trace.p,d_lde.p,d_powers.p,n,m,64);HIP_CHECK(hipGetLastError());
    t.gpu_coset_ms+=gt.stop();
    auto fwd=gpu_ntt_general(d_lde.p,m,64,false,&t.h2d_ms);t.gpu_fwd_ntt_ms+=fwd.total_ms;

    auto trace_tree=build_canonical_tree(d_lde.p,m,64);t.gpu_trace_merkle_ms+=trace_tree.total_ms;
    h=host_ms_now();trace_root_out=tree_root(trace_tree);t.d2h_compact_ms+=host_ms_now()-h;
    qm::PublicInput pub;for(int i=0;i<16;++i){pub.initial[i]=qm::F(initial[i]);pub.final_acc[i]=qm::F(final_acc[i]);}
    qm::Transcript tr;auto pd=qm::public_digest(trace_log,pub);tr.absorb_digest(qm::Domain::Hash,pd);
    tr.absorb_digest(qm::Domain::Leaf,to_digest(trace_root_out));auto alpha=tr.challenge_ext();

    DeviceBuf d_q((size_t)m*2);
    u64 omega_m=g64_pow_u64(G64_ROOT_2_32,(1ULL<<32)/(u64)m);
    u64 omega_n=g64_pow_u64(G64_ROOT_2_32,(1ULL<<32)/(u64)n);
    u64 last=g64_pow_u64(omega_n,G64_P-2);
    gt.start();composition_kernel<<<(m+255)/256,256>>>(d_lde.p,(Dp2*)d_q.p,m,d_init.p,d_final.p,
        alpha.a.v,alpha.b.v,omega_m,last,(u64)n);HIP_CHECK(hipGetLastError());t.gpu_composition_ms+=gt.stop();

    std::vector<LayerRetained> retained;retained.reserve(layers);
    DeviceBuf cur=std::move(d_q);int rows=m;u64 offset=7;
    qm::Proof proof;proof.log_n=trace_log;proof.pub=pub;proof.trace_root=to_digest(trace_root_out);
    std::vector<qm::E> betas;
    while(rows>16){
        LayerRetained lr;lr.rows=rows;lr.values=std::move(cur);lr.tree=build_canonical_tree(lr.values.p,rows,2);
        t.gpu_fri_merkle_ms+=lr.tree.total_ms;
        h=host_ms_now();auto root=tree_root(lr.tree);t.d2h_compact_ms+=host_ms_now()-h;qm::Digest rd=to_digest(root);
        if(retained.empty())proof.quotient_root=rd;else proof.intermediate_roots.push_back(rd);
        tr.absorb_digest(qm::Domain::Fri,rd);qm::E beta=tr.challenge_ext();betas.push_back(beta);
        int half=rows/2;DeviceBuf next((size_t)half*2);
        u64 omega=g64_pow_u64(G64_ROOT_2_32,(1ULL<<32)/(u64)rows);
        gt.start();fri_fold_canonical_kernel<<<(half+255)/256,256>>>((Dp2*)lr.values.p,(Dp2*)next.p,half,
            beta.a.v,beta.b.v,offset,omega);HIP_CHECK(hipGetLastError());t.gpu_fri_fold_ms+=gt.stop();
        retained.push_back(std::move(lr));cur=std::move(next);rows=half;offset=g64_mul(offset,offset);
    }
    std::array<Dp2,16> terminal{};
    h=host_ms_now();HIP_CHECK(hipMemcpy(terminal.data(),cur.p,terminal.size()*sizeof(Dp2),hipMemcpyDeviceToHost));t.d2h_compact_ms+=host_ms_now()-h;
    proof.terminal.resize(16);std::vector<qm::F> te;te.reserve(32);
    for(int i=0;i<16;++i){proof.terminal[i]=qm::E(qm::F(terminal[i].a),qm::F(terminal[i].b));te.push_back(qm::F(terminal[i].a));te.push_back(qm::F(terminal[i].b));}
    tr.absorb_digest(qm::Domain::Fri,qm::hash_fields(te,qm::Domain::Fri));
    std::array<u64,64> queries{};for(auto&q:queries)q=tr.challenge_index((uint32_t)m);

    const size_t stride=opening_words_per_query(height,layers);DeviceBuf d_queries(64),d_open(stride*64);
    h=host_ms_now();HIP_CHECK(hipMemcpy(d_queries.p,queries.data(),512,hipMemcpyHostToDevice));t.h2d_ms+=host_ms_now()-h;
    gt.start();extract_trace_openings_kernel<<<64,256>>>(d_lde.p,trace_tree.storage.p,d_queries.p,d_open.p,m,height,stride);
    HIP_CHECK(hipGetLastError());
    size_t layer_off=64+height*4+64+height*4;
    for(int l=0;l<layers;++l){
        extract_fri_openings_kernel<<<64,1>>>((Dp2*)retained[l].values.p,retained[l].tree.storage.p,d_queries.p,
            d_open.p,retained[l].rows,height-l,stride,layer_off);
        HIP_CHECK(hipGetLastError());layer_off+=fri_layer_words(height-l);
    }
    t.gpu_openings_ms+=gt.stop();
    std::vector<u64> open(stride*64);h=host_ms_now();HIP_CHECK(hipMemcpy(open.data(),d_open.p,open.size()*8,hipMemcpyDeviceToHost));t.d2h_compact_ms+=host_ms_now()-h;

    proof.queries.resize(64);
    for(int qi=0;qi<64;++qi){
        auto&qp=proof.queries[qi];qp.idx=(uint32_t)queries[qi];size_t p=(size_t)qi*stride;
        for(int j=0;j<64;++j)qp.cur.row[j]=qm::F(open[p++]);
        qp.cur.path.resize(height);for(int l=0;l<height;++l)for(int k=0;k<4;++k)qp.cur.path[l][k]=qm::F(open[p++]);
        for(int j=0;j<64;++j)qp.nxt.row[j]=qm::F(open[p++]);
        qp.nxt.path.resize(height);for(int l=0;l<height;++l)for(int k=0;k<4;++k)qp.nxt.path[l][k]=qm::F(open[p++]);
        qp.layers.resize(layers);
        for(int l=0;l<layers;++l){auto&fp=qp.layers[l];fp.lo=qm::E(qm::F(open[p]),qm::F(open[p+1]));fp.hi=qm::E(qm::F(open[p+2]),qm::F(open[p+3]));p+=4;
            int ph=height-l;fp.plo.resize(ph);for(int z=0;z<ph;++z)for(int k=0;k<4;++k)fp.plo[z][k]=qm::F(open[p++]);
            fp.phi.resize(ph);for(int z=0;z<ph;++z)for(int k=0;k<4;++k)fp.phi[z][k]=qm::F(open[p++]);}
        if(p!=(size_t)(qi+1)*stride)throw std::runtime_error("opening layout mismatch");
    }
    t.total_ms+=host_ms_now()-total_start;return proof;
}

static void append_report(const std::string&path,int run,const OptionsFinal&o,const Timings&t,
                          const std::array<u64,4>&root,size_t bytes,u64 fnv,bool verify_ok){
    bool fresh=!std::filesystem::exists(path);std::ofstream f(path,std::ios::app);if(!f)throw std::runtime_error("cannot write report");
    if(fresh)f<<"run,scale,total_lde_elements,lde_rows,trace_rows,trace_root,proof_bytes,proof_fnv,verify,cpu_lde_ms,witness_io_ms,h2d_ms,gpu_trace_ms,gpu_inverse_ntt_ms,gpu_coset_ms,gpu_forward_ntt_ms,gpu_trace_merkle_ms,gpu_composition_ms,gpu_fri_merkle_ms,gpu_fri_fold_ms,gpu_openings_ms,d2h_compact_ms,serialization_ms,verification_ms,file_io_ms,total_ms\n";
    f<<run<<","<<o.scale<<","<<(1ULL<<o.scale)<<","<<(1ULL<<(o.scale-6))<<","<<(1ULL<<(o.scale-9))<<",\""<<digest_text(root)<<"\","<<bytes<<","<<qm::hx(fnv)<<","<<(verify_ok?1:0)<<",0,"<<std::fixed<<std::setprecision(3)
     <<t.witness_io_ms<<","<<t.h2d_ms<<","<<t.gpu_trace_ms<<","<<t.gpu_inv_ntt_ms<<","<<t.gpu_coset_ms<<","<<t.gpu_fwd_ntt_ms<<","<<t.gpu_trace_merkle_ms<<","<<t.gpu_composition_ms<<","<<t.gpu_fri_merkle_ms<<","<<t.gpu_fri_fold_ms<<","<<t.gpu_openings_ms<<","<<t.d2h_compact_ms<<","<<t.serialization_ms<<","<<t.verification_ms<<","<<t.file_io_ms<<","<<t.total_ms<<"\n";
}

} // namespace qmgpu

int main(int argc,char**argv){
    try{
        using namespace qmgpu;auto o=parse(argc,argv);
        auto frozen=load_poseidon2_constants(o.constants);upload_poseidon2_constants(frozen);
        std::vector<uint8_t> baseline;std::array<u64,4> baseline_root{};u64 baseline_fnv=0;
        for(int run=1;run<=o.repeat;++run){
            Timings t;std::array<u64,4> root{};auto proof=run_once(o,t,root);
            double a=host_ms_now();auto bytes=qm::encode(proof);t.serialization_ms=host_ms_now()-a;
            auto expected=proof.pub;a=host_ms_now();bool ok=qm::verify(bytes,expected);t.verification_ms=host_ms_now()-a;
            if(!ok)throw std::runtime_error("canonical verifier rejected GPU proof");
            u64 fnv=qm::fnv1a(bytes);
            if(run==1){baseline=bytes;baseline_root=root;baseline_fnv=fnv;}
            else if(bytes!=baseline||root!=baseline_root||fnv!=baseline_fnv)throw std::runtime_error("determinism failure across repeated runs");
            std::string out=o.proof_out;if(o.repeat>1){auto pos=out.rfind('.');out=(pos==std::string::npos?out+".run-"+std::to_string(run):out.substr(0,pos)+".run-"+std::to_string(run)+out.substr(pos));}
            if(!o.no_write){a=host_ms_now();std::filesystem::create_directories(std::filesystem::path(out).parent_path().empty()?".":std::filesystem::path(out).parent_path());std::ofstream f(out,std::ios::binary);f.write((char*)bytes.data(),bytes.size());f.close();if(!f)throw std::runtime_error("proof write failed");t.file_io_ms=host_ms_now()-a;}
            t.total_ms+=t.serialization_ms+t.verification_ms+t.file_io_ms;
            if(!o.report_out.empty())append_report(o.report_out,run,o,t,root,bytes.size(),fnv,ok);
            std::cout<<"status=PASS\nimplementation=rx7900xtx_24g_backend\nscale_sweep=READY\ndeterminism="<<(o.repeat>1?"PASS":"NOT_RUN")
                     <<"\ntiming_breakdown=PASS\ndirect_gpu_lde=PASS\ndevice_resident_openings=PASS\nscale_log2="<<o.scale
                     <<"\ntrace_log2="<<o.scale-9<<"\nlde_rows="<<(1ULL<<(o.scale-6))<<"\nfri_fold_rounds="<<o.scale-10
                     <<"\nquery_count=64\nterminal_elements=16\ntrace_root="<<digest_text(root)<<"\nproof_bytes="<<bytes.size()
                     <<"\nproof_fnv="<<qm::hx(fnv)<<"\nverifier=PASS\nrun="<<run<<"\n";
        }
        return 0;
    }catch(const std::exception&e){std::cerr<<"ERROR: "<<e.what()<<"\n";return 1;}
}
