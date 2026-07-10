// SPDX-License-Identifier: Apache-2.0
// qingming_verifier_g64.cpp
//
// Standalone CPU verifier for QINGMING-PROOF-G64 v1.
//
// Build:
//   g++ -O3 -std=c++17 qingming_verifier_g64.cpp -o qingming_verifier_g64
//
// Run:
//   ./qingming_verifier_g64 qingming_poseidon2_g64_constants.h proof.qmp
//
// Verifies:
//   - proof header
//   - Poseidon2 frozen params fingerprint
//   - all field elements canonical
//   - final root from final_values
//   - transcript query indices
//   - transcript FRI betas
//   - pair Merkle openings for every query/round
//   - fold consistency from layer to layer
//
// QINGMING-PROOF-G64 v1 is fixed:
//   final_rows = 1
//   fri_query_count = 32
//   beta = Poseidon2(TRANSCRIPT, root[4] || round)[0]
//   query_index = Poseidon2(TRANSCRIPT, all_roots || final_values || query_counter)[0] & (layer0_rows - 1)

#include <algorithm>
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
static constexpr u64 G64_ROOT_2_32 = 0x185629dcda58878cULL;

static constexpr int P2_T = 12;
static constexpr int P2_RATE = 8;
static constexpr int P2_DIGEST = 4;
static constexpr int P2_RF = 8;
static constexpr int P2_RP = 22;

static constexpr int P2_RC_EXT_LEN = P2_RF * P2_T;
static constexpr int P2_RC_INT_LEN = P2_RP;
static constexpr int P2_MATRIX_LEN = P2_T * P2_T;
static constexpr int P2_DIAG_LEN = P2_T;
static constexpr int P2_DOMAIN_LEN = 6;

static constexpr int QMP_G64_V1_QUERY_COUNT = 32;

enum DomainIndex : int {
    DOMAIN_PERMUTATION_TEST = 0,
    DOMAIN_HASH_ELEMENTS    = 1,
    DOMAIN_MERKLE_LEAF      = 2,
    DOMAIN_MERKLE_NODE      = 3,
    DOMAIN_FRI_COMMITMENT   = 4,
    DOMAIN_TRANSCRIPT       = 5
};

struct FrozenPoseidon2 {
    std::vector<u64> rc_ext;
    std::vector<u64> rc_int;
    std::vector<u64> matrix;
    std::vector<u64> diag;
    std::vector<u64> domains;
    u64 params_fingerprint = 0;
    u64 vectors_fingerprint = 0;
};

struct QmpHeader {
    u64 version = 0;
    u64 poseidon2_params_fingerprint = 0;
    u64 poseidon2_test_vectors_fingerprint = 0;
    u64 ntt_root_2_32 = 0;
    u64 scale_log2 = 0;
    u64 committed_columns = 0;
    u64 layer0_rows = 0;
    u64 final_rows = 0;
    u64 fri_rounds = 0;
    u64 fri_root_count = 0;
    u64 fri_query_count = 0;
};

struct FriOpening {
    std::vector<u64> even;
    std::vector<u64> odd;
    std::vector<u64> path;
};

struct Proof {
    QmpHeader h;
    std::vector<u64> roots;
    std::vector<u64> final_values;
    std::vector<std::vector<FriOpening>> openings; // [query][round]
};

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

static std::string read_all_text(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open file: " + path);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

static std::vector<uint8_t> read_all_binary(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open proof file: " + path);

    in.seekg(0, std::ios::end);
    std::streamoff n = in.tellg();
    in.seekg(0, std::ios::beg);

    if (n < 0) throw std::runtime_error("bad proof file size");

    std::vector<uint8_t> bytes((size_t)n);
    if (!bytes.empty()) {
        in.read((char*)bytes.data(), n);
    }

    if (!in && n != 0) throw std::runtime_error("failed to read proof file");
    return bytes;
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
    const std::string text = read_all_text(path);

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

static u64 read_u64_le(const std::vector<uint8_t>& bytes, size_t& off) {
    if (off + 8 > bytes.size()) throw std::runtime_error("unexpected end of proof");

    u64 x = 0;
    for (int i = 0; i < 8; ++i) {
        x |= ((u64)bytes[off + i]) << (8 * i);
    }

    off += 8;
    return x;
}

static std::vector<u64> read_u64_vec(const std::vector<uint8_t>& bytes, size_t& off, size_t n, const char* name) {
    std::vector<u64> out;
    out.reserve(n);

    for (size_t i = 0; i < n; ++i) {
        u64 x = read_u64_le(bytes, off);
        if (x >= G64_P) {
            std::ostringstream os;
            os << name << " contains non-canonical field element at " << i;
            throw std::runtime_error(os.str());
        }
        out.push_back(x);
    }

    return out;
}

static u64 g64_add(u64 a, u64 b) {
    u64 res = a + b;
    if (res < a) res += 0x00000000ffffffffULL;
    if (res >= G64_P) res -= G64_P;
    return res;
}

static u64 g64_sub(u64 a, u64 b) {
    u64 res = a - b;
    if (a < b) res -= 0x00000000ffffffffULL;
    return res;
}

static u64 g64_mul(u64 a, u64 b) {
    return (u64)(((u128)a * b) % G64_P);
}

static u64 g64_pow7(u64 x) {
    u64 x2 = g64_mul(x, x);
    u64 x3 = g64_mul(x2, x);
    u64 x4 = g64_mul(x2, x2);
    return g64_mul(x3, x4);
}

static void cpu_poseidon2_perm(u64 state[P2_T], const FrozenPoseidon2& f) {
    constexpr int HALF = P2_RF / 2;

    for (int r = 0; r < HALF; ++r) {
        for (int i = 0; i < P2_T; ++i) state[i] = g64_add(state[i], f.rc_ext[r * P2_T + i]);
        for (int i = 0; i < P2_T; ++i) state[i] = g64_pow7(state[i]);

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
        for (int i = 0; i < P2_T; ++i) out[i] = g64_add(g64_mul(f.diag[i], state[i]), total);
        for (int i = 0; i < P2_T; ++i) state[i] = out[i];
    }

    for (int r = HALF; r < P2_RF; ++r) {
        for (int i = 0; i < P2_T; ++i) state[i] = g64_add(state[i], f.rc_ext[r * P2_T + i]);
        for (int i = 0; i < P2_T; ++i) state[i] = g64_pow7(state[i]);

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

static void merkle_leaf(const std::vector<u64>& values, const FrozenPoseidon2& f, u64 digest[P2_DIGEST]) {
    cpu_hash_elements(values, DOMAIN_MERKLE_LEAF, f, digest);
}

static void merkle_node(const u64 left[P2_DIGEST], const u64 right[P2_DIGEST], const FrozenPoseidon2& f, u64 parent[P2_DIGEST]) {
    std::vector<u64> values;
    values.reserve(8);
    for (int i = 0; i < P2_DIGEST; ++i) values.push_back(left[i]);
    for (int i = 0; i < P2_DIGEST; ++i) values.push_back(right[i]);
    cpu_hash_elements(values, DOMAIN_MERKLE_NODE, f, parent);
}

static u64 derive_beta(const u64 root[P2_DIGEST], int round, const FrozenPoseidon2& f) {
    std::vector<u64> input;
    input.reserve(5);
    for (int i = 0; i < P2_DIGEST; ++i) input.push_back(root[i]);
    input.push_back((u64)round);

    u64 digest[P2_DIGEST];
    cpu_hash_elements(input, DOMAIN_TRANSCRIPT, f, digest);
    return digest[0];
}

static std::vector<u64> transcript_query_indices(
    const std::vector<u64>& roots,
    const std::vector<u64>& final_values,
    int query_count,
    int layer0_rows,
    const FrozenPoseidon2& f
) {
    std::vector<u64> indices;
    indices.reserve(query_count);

    for (int q = 0; q < query_count; ++q) {
        std::vector<u64> input;
        input.reserve(roots.size() + final_values.size() + 1);

        for (u64 x : roots) input.push_back(x);
        for (u64 x : final_values) input.push_back(x);
        input.push_back((u64)q);

        u64 digest[P2_DIGEST];
        cpu_hash_elements(input, DOMAIN_TRANSCRIPT, f, digest);
        indices.push_back(digest[0] & ((u64)layer0_rows - 1));
    }

    return indices;
}

static bool digest_equal(const u64 a[P2_DIGEST], const u64* b) {
    for (int i = 0; i < P2_DIGEST; ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}


// -----------------------------
// QSPG64 full STARK proof verifier
// -----------------------------

static constexpr u64 QM_STARK_TAG_PUBLIC_INPUT = 0x5153505f50554249ULL;
static constexpr u64 QM_STARK_TAG_STATEMENT    = 0x5153505f53544d54ULL;
static constexpr u64 QM_STARK_TAG_ALPHA        = 0x5153505f414c5048ULL;
static constexpr u64 QM_STARK_TAG_QUERY        = 0x5153505f51554552ULL;
static constexpr u64 QSPG64_AIR_PROFILE_GEOCLOCK = 1;
static constexpr int QM_STARK_LDE = 8;

struct QspHeader {
    u64 format_revision = 0;
    u64 poseidon2_params_fingerprint = 0;
    u64 poseidon2_test_vectors_fingerprint = 0;
    u64 ntt_root_2_32 = 0;
    u64 scale_log2 = 0;
    u64 lde_factor = 0;
    u64 layer0_rows = 0;
    u64 trace_columns = 0;
    u64 quotient_columns = 0;
    u64 final_rows = 0;
    u64 fri_rounds = 0;
    u64 fri_root_count = 0;
    u64 fri_query_count = 0;
    u64 air_profile_id = 0;
    u64 public_input_count = 0;
    u64 transition_ratio = 0;
    u64 alpha = 0;
};

struct QspProof {
    QspHeader h;
    std::vector<u64> public_input_digest;
    std::vector<u64> statement_digest;
    std::vector<u64> trace_root;
    std::vector<u64> quotient_roots;
    std::vector<u64> final_values;
    std::vector<std::vector<FriOpening>> quotient_openings; // [query][round]

    struct TraceOpening {
        std::vector<u64> current_values;
        std::vector<u64> current_path;
        std::vector<u64> next_values;
        std::vector<u64> next_path;
    };

    std::vector<TraceOpening> trace_openings; // [query]
};

static void digest_public_inputs_geoclock(
    u64 transition_ratio,
    const FrozenPoseidon2& f,
    u64 digest[P2_DIGEST]
) {
    std::vector<u64> input;
    input.push_back(QM_STARK_TAG_PUBLIC_INPUT);
    input.push_back(1);
    input.push_back(transition_ratio);
    cpu_hash_elements(input, DOMAIN_TRANSCRIPT, f, digest);
}

static void digest_statement_geoclock(
    int scale_log2,
    int rows,
    int cols,
    u64 transition_ratio,
    const u64 public_input_digest[P2_DIGEST],
    const FrozenPoseidon2& f,
    u64 digest[P2_DIGEST]
) {
    static constexpr u64 AIR_ID0 = 0x514d5f4149525f47ULL;
    static constexpr u64 AIR_ID1 = 0x454f434c4f434b5fULL;
    static constexpr u64 AIR_ID2 = 0x4736345f56315f00ULL;
    static constexpr u64 AIR_ID3 = 0x0000000000000002ULL;

    std::vector<u64> input;
    input.push_back(QM_STARK_TAG_STATEMENT);
    input.push_back(AIR_ID0);
    input.push_back(AIR_ID1);
    input.push_back(AIR_ID2);
    input.push_back(AIR_ID3);
    for (int i = 0; i < P2_DIGEST; ++i) input.push_back(public_input_digest[i]);
    input.push_back((u64)scale_log2);
    input.push_back((u64)rows);
    input.push_back((u64)cols);
    input.push_back((u64)cols);
    input.push_back((u64)cols);
    input.push_back((u64)QM_STARK_LDE);
    input.push_back(transition_ratio);
    cpu_hash_elements(input, DOMAIN_TRANSCRIPT, f, digest);
}

static u64 derive_composition_alpha_geoclock(
    const u64 statement_digest[P2_DIGEST],
    const u64 trace_root[P2_DIGEST],
    const FrozenPoseidon2& f
) {
    std::vector<u64> input;
    input.push_back(QM_STARK_TAG_ALPHA);
    for (int i = 0; i < P2_DIGEST; ++i) input.push_back(statement_digest[i]);
    for (int i = 0; i < P2_DIGEST; ++i) input.push_back(trace_root[i]);
    input.push_back(0);

    u64 digest[P2_DIGEST];
    cpu_hash_elements(input, DOMAIN_TRANSCRIPT, f, digest);
    return digest[0];
}

static std::vector<u64> stark_query_indices(
    const u64 statement_digest[P2_DIGEST],
    const u64 trace_root[P2_DIGEST],
    const std::vector<u64>& quotient_roots,
    const std::vector<u64>& final_values,
    int query_count,
    int rows,
    const FrozenPoseidon2& f
) {
    std::vector<u64> out;
    out.reserve(query_count);
    for (int q = 0; q < query_count; ++q) {
        std::vector<u64> input;
        input.push_back(QM_STARK_TAG_QUERY);
        for (int i = 0; i < P2_DIGEST; ++i) input.push_back(statement_digest[i]);
        for (int i = 0; i < P2_DIGEST; ++i) input.push_back(trace_root[i]);
        for (u64 x : quotient_roots) input.push_back(x);
        for (u64 x : final_values) input.push_back(x);
        input.push_back((u64)q);

        u64 digest[P2_DIGEST];
        cpu_hash_elements(input, DOMAIN_TRANSCRIPT, f, digest);
        out.push_back(digest[0] & ((u64)rows - 1));
    }
    return out;
}

static QspProof read_qsp_proof(const std::string& path) {
    const std::vector<uint8_t> bytes = read_all_binary(path);
    size_t off = 0;
    if (bytes.size() < 8) throw std::runtime_error("proof too small");
    const unsigned char expect[8] = {'Q','S','P','G','6','4','\0','\0'};
    for (int i = 0; i < 8; ++i) {
        if (bytes[i] != expect[i]) throw std::runtime_error("bad QSPG64 proof magic");
    }
    off = 8;

    QspProof p;
    p.h.format_revision = read_u64_le(bytes, off);
    p.h.poseidon2_params_fingerprint = read_u64_le(bytes, off);
    p.h.poseidon2_test_vectors_fingerprint = read_u64_le(bytes, off);
    p.h.ntt_root_2_32 = read_u64_le(bytes, off);
    p.h.scale_log2 = read_u64_le(bytes, off);
    p.h.lde_factor = read_u64_le(bytes, off);
    p.h.layer0_rows = read_u64_le(bytes, off);
    p.h.trace_columns = read_u64_le(bytes, off);
    p.h.quotient_columns = read_u64_le(bytes, off);
    p.h.final_rows = read_u64_le(bytes, off);
    p.h.fri_rounds = read_u64_le(bytes, off);
    p.h.fri_root_count = read_u64_le(bytes, off);
    p.h.fri_query_count = read_u64_le(bytes, off);
    p.h.air_profile_id = read_u64_le(bytes, off);
    p.h.public_input_count = read_u64_le(bytes, off);
    p.h.transition_ratio = read_u64_le(bytes, off);
    p.h.alpha = read_u64_le(bytes, off);

    if (p.h.format_revision != 1) throw std::runtime_error("unsupported QSPG64 format revision");
    if (p.h.ntt_root_2_32 != G64_ROOT_2_32) throw std::runtime_error("wrong ntt_root_2_32");
    if (p.h.lde_factor != QM_STARK_LDE) throw std::runtime_error("wrong lde_factor");
    if (p.h.final_rows != 1) throw std::runtime_error("QSPG64 requires final_rows = 1");
    if (p.h.fri_query_count != QMP_G64_V1_QUERY_COUNT) throw std::runtime_error("QSPG64 requires fri_query_count = 32");
    if (p.h.air_profile_id != QSPG64_AIR_PROFILE_GEOCLOCK) throw std::runtime_error("unsupported AIR profile id");
    if (p.h.public_input_count != 1) throw std::runtime_error("GEOCLOCK requires one public input");
    if (p.h.trace_columns != p.h.quotient_columns) throw std::runtime_error("current GEOCLOCK verifier expects trace_columns == quotient_columns");
    if (!is_power_of_two_u64(p.h.layer0_rows)) throw std::runtime_error("layer0_rows must be power of two");

    const u64 scale = p.h.layer0_rows * p.h.trace_columns;
    if (!is_power_of_two_u64(scale)) throw std::runtime_error("scale must be power of two");
    if ((u64)log2_u64(scale) != p.h.scale_log2) throw std::runtime_error("scale_log2 mismatch");
    if (p.h.fri_rounds != (u64)log2_u64(p.h.layer0_rows)) throw std::runtime_error("fri_rounds mismatch");
    if (p.h.fri_root_count != p.h.fri_rounds + 1) throw std::runtime_error("fri_root_count mismatch");

    p.public_input_digest = read_u64_vec(bytes, off, P2_DIGEST, "public_input_digest");
    p.statement_digest = read_u64_vec(bytes, off, P2_DIGEST, "statement_digest");
    p.trace_root = read_u64_vec(bytes, off, P2_DIGEST, "trace_root");
    p.quotient_roots = read_u64_vec(bytes, off, (size_t)p.h.fri_root_count * P2_DIGEST, "quotient_roots");
    p.final_values = read_u64_vec(bytes, off, (size_t)p.h.quotient_columns, "final_values");

    p.quotient_openings.resize((size_t)p.h.fri_query_count);
    for (size_t q = 0; q < p.h.fri_query_count; ++q) {
        p.quotient_openings[q].resize((size_t)p.h.fri_rounds);
        for (size_t r = 0; r < p.h.fri_rounds; ++r) {
            const u64 rows = p.h.layer0_rows >> r;
            const int height = log2_u64(rows);
            const int path_len = height - 1;

            FriOpening op;
            op.even = read_u64_vec(bytes, off, (size_t)p.h.quotient_columns, "quotient_even");
            op.odd = read_u64_vec(bytes, off, (size_t)p.h.quotient_columns, "quotient_odd");
            op.path = read_u64_vec(bytes, off, (size_t)path_len * P2_DIGEST, "quotient_path");
            p.quotient_openings[q][r] = std::move(op);
        }
    }

    const int trace_height = log2_u64(p.h.layer0_rows);
    p.trace_openings.resize((size_t)p.h.fri_query_count);
    for (size_t q = 0; q < p.h.fri_query_count; ++q) {
        QspProof::TraceOpening op;
        op.current_values = read_u64_vec(bytes, off, (size_t)p.h.trace_columns, "trace_current_values");
        op.current_path = read_u64_vec(bytes, off, (size_t)trace_height * P2_DIGEST, "trace_current_path");
        op.next_values = read_u64_vec(bytes, off, (size_t)p.h.trace_columns, "trace_next_values");
        op.next_path = read_u64_vec(bytes, off, (size_t)trace_height * P2_DIGEST, "trace_next_path");
        p.trace_openings[q] = std::move(op);
    }

    if (off != bytes.size()) {
        std::ostringstream os;
        os << "trailing proof bytes: " << (bytes.size() - off);
        throw std::runtime_error(os.str());
    }

    return p;
}

static void verify_pair_opening_qsp(
    const FriOpening& op,
    const u64* root,
    u64 idx_current,
    u64 rows,
    const FrozenPoseidon2& f
) {
    const int height = log2_u64(rows);
    const int path_len = height - 1;

    if ((int)op.path.size() != path_len * P2_DIGEST) throw std::runtime_error("bad quotient path length");

    u64 leaf_even[P2_DIGEST];
    u64 leaf_odd[P2_DIGEST];
    u64 cur[P2_DIGEST];

    merkle_leaf(op.even, f, leaf_even);
    merkle_leaf(op.odd, f, leaf_odd);
    merkle_node(leaf_even, leaf_odd, f, cur);

    u64 pair_index = idx_current >> 1;

    for (int l = 0; l < path_len; ++l) {
        const u64* sib = &op.path[(size_t)l * P2_DIGEST];
        u64 next[P2_DIGEST];
        const int bit = (int)((pair_index >> l) & 1ULL);

        if (bit == 0) merkle_node(cur, sib, f, next);
        else merkle_node(sib, cur, f, next);

        for (int i = 0; i < P2_DIGEST; ++i) cur[i] = next[i];
    }

    if (!digest_equal(cur, root)) {
        std::ostringstream os;
        os << "quotient pair opening root mismatch for idx=" << idx_current << " rows=" << rows;
        throw std::runtime_error(os.str());
    }
}

static void verify_leaf_opening_qsp(
    const std::vector<u64>& values,
    const std::vector<u64>& path,
    const u64* root,
    u64 row,
    u64 rows,
    const FrozenPoseidon2& f
) {
    const int height = log2_u64(rows);
    if ((int)path.size() != height * P2_DIGEST) throw std::runtime_error("bad trace path length");

    u64 cur[P2_DIGEST];
    merkle_leaf(values, f, cur);

    for (int l = 0; l < height; ++l) {
        const u64* sib = &path[(size_t)l * P2_DIGEST];
        u64 next[P2_DIGEST];
        const int bit = (int)((row >> l) & 1ULL);

        if (bit == 0) merkle_node(cur, sib, f, next);
        else merkle_node(sib, cur, f, next);

        for (int i = 0; i < P2_DIGEST; ++i) cur[i] = next[i];
    }

    if (!digest_equal(cur, root)) {
        std::ostringstream os;
        os << "trace leaf opening root mismatch for row=" << row;
        throw std::runtime_error(os.str());
    }
}

static void verify_qsp_proof(const QspProof& p, const FrozenPoseidon2& f) {
    if (p.h.poseidon2_params_fingerprint != f.params_fingerprint) throw std::runtime_error("Poseidon2 params fingerprint mismatch");
    if (p.h.poseidon2_test_vectors_fingerprint != f.vectors_fingerprint) throw std::runtime_error("Poseidon2 test vectors fingerprint mismatch");
    if (fingerprint_poseidon2_params(f) != f.params_fingerprint) throw std::runtime_error("local Poseidon2 params fingerprint mismatch");

    u64 computed_public_digest[P2_DIGEST];
    digest_public_inputs_geoclock(p.h.transition_ratio, f, computed_public_digest);
    if (!digest_equal(computed_public_digest, p.public_input_digest.data())) throw std::runtime_error("public input digest mismatch");

    u64 computed_statement_digest[P2_DIGEST];
    digest_statement_geoclock(
        (int)p.h.scale_log2,
        (int)p.h.layer0_rows,
        (int)p.h.trace_columns,
        p.h.transition_ratio,
        computed_public_digest,
        f,
        computed_statement_digest
    );
    if (!digest_equal(computed_statement_digest, p.statement_digest.data())) throw std::runtime_error("statement digest mismatch");

    const u64 computed_alpha = derive_composition_alpha_geoclock(computed_statement_digest, p.trace_root.data(), f);
    if (computed_alpha != p.h.alpha) throw std::runtime_error("composition alpha mismatch");

    u64 computed_final_root[P2_DIGEST];
    merkle_leaf(p.final_values, f, computed_final_root);
    const u64* proof_final_root = &p.quotient_roots[(size_t)(p.h.fri_root_count - 1) * P2_DIGEST];
    if (!digest_equal(computed_final_root, proof_final_root)) throw std::runtime_error("final root mismatch");

    std::vector<u64> query_indices = stark_query_indices(
        computed_statement_digest,
        p.trace_root.data(),
        p.quotient_roots,
        p.final_values,
        (int)p.h.fri_query_count,
        (int)p.h.layer0_rows,
        f
    );

    for (size_t q = 0; q < p.h.fri_query_count; ++q) {
        const u64 idx0 = query_indices[q];
        const u64 next_idx = (idx0 + QM_STARK_LDE) & (p.h.layer0_rows - 1);

        const auto& tr = p.trace_openings[q];
        verify_leaf_opening_qsp(tr.current_values, tr.current_path, p.trace_root.data(), idx0, p.h.layer0_rows, f);
        verify_leaf_opening_qsp(tr.next_values, tr.next_path, p.trace_root.data(), next_idx, p.h.layer0_rows, f);

        u64 idx = idx0;
        for (size_t r = 0; r < p.h.fri_rounds; ++r) {
            const u64 rows = p.h.layer0_rows >> r;
            const FriOpening& op = p.quotient_openings[q][r];
            const u64* root_r = &p.quotient_roots[r * P2_DIGEST];
            verify_pair_opening_qsp(op, root_r, idx, rows, f);

            const u64 beta = derive_beta(root_r, (int)r, f);
            std::vector<u64> folded((size_t)p.h.quotient_columns);
            for (size_t c = 0; c < p.h.quotient_columns; ++c) {
                folded[c] = g64_add(op.even[c], g64_mul(beta, op.odd[c]));
            }

            const u64 idx_next = idx >> 1;
            if (r + 1 < p.h.fri_rounds) {
                const FriOpening& next_op = p.quotient_openings[q][r + 1];
                const std::vector<u64>& expected = ((idx_next & 1ULL) == 0) ? next_op.even : next_op.odd;
                for (size_t c = 0; c < p.h.quotient_columns; ++c) {
                    if (folded[c] != expected[c]) throw std::runtime_error("FRI fold consistency mismatch");
                }
            } else {
                for (size_t c = 0; c < p.h.quotient_columns; ++c) {
                    if (folded[c] != p.final_values[c]) throw std::runtime_error("final fold mismatch");
                }
            }
            idx = idx_next;
        }

        const FriOpening& layer0 = p.quotient_openings[q][0];
        const std::vector<u64>& q_values = ((idx0 & 1ULL) == 0) ? layer0.even : layer0.odd;

        for (size_t c = 0; c < p.h.trace_columns; ++c) {
            const u64 constraint = g64_sub(tr.next_values[c], g64_mul(p.h.transition_ratio, tr.current_values[c]));
            const u64 expected_q = g64_mul(p.h.alpha, constraint);
            if (expected_q != q_values[c]) {
                std::ostringstream os;
                os << "local AIR quotient relation mismatch q=" << q << " col=" << c;
                throw std::runtime_error(os.str());
            }
        }
    }
}

static void print_digest(const char* name, const u64* d) {
    std::cout << name << ": [";
    for (int i = 0; i < P2_DIGEST; ++i) {
        if (i) std::cout << ", ";
        std::cout << hex64(d[i]);
    }
    std::cout << "]\n";
}

static void usage(const char* argv0) {
    std::cerr << "Usage:\n";
    std::cerr << "  g++ -O3 -std=c++17 qingming_stark_g64_verifier.cpp -o qingming_stark_g64_verifier\n";
    std::cerr << "  " << argv0 << " qingming_poseidon2_g64_constants.h proof.qsp\n";
}

int main(int argc, char** argv) {
    try {
        if (argc != 3) {
            usage(argv[0]);
            return 2;
        }

        FrozenPoseidon2 constants = load_poseidon2_constants(argv[1]);
        QspProof proof = read_qsp_proof(argv[2]);
        verify_qsp_proof(proof, constants);

        const u64* quotient_root = &proof.quotient_roots[0];
        const u64* final_root = &proof.quotient_roots[(size_t)(proof.h.fri_root_count - 1) * P2_DIGEST];

        std::cout << "QINGMING-STARK-G64 verifier\n";
        std::cout << "status: PASS\n";
        std::cout << "proof_format: QSPG64\n";
        std::cout << "air_profile: QINGMING-AIR-GEOCLOCK-G64\n";
        std::cout << "field: Goldilocks/G64\n";
        std::cout << "p: " << G64_P << "\n";
        std::cout << "hash: QINGMING-POSEIDON2-G64\n";
        std::cout << "poseidon2_params_fingerprint: " << hex64(constants.params_fingerprint) << "\n";
        std::cout << "poseidon2_test_vectors_fingerprint: " << hex64(constants.vectors_fingerprint) << "\n";
        std::cout << "scale_log2: " << proof.h.scale_log2 << "\n";
        std::cout << "lde_factor: " << proof.h.lde_factor << "\n";
        std::cout << "layer0_rows: " << proof.h.layer0_rows << "\n";
        std::cout << "trace_columns: " << proof.h.trace_columns << "\n";
        std::cout << "quotient_columns: " << proof.h.quotient_columns << "\n";
        std::cout << "final_rows: " << proof.h.final_rows << "\n";
        std::cout << "fri_rounds: " << proof.h.fri_rounds << "\n";
        std::cout << "fri_root_count: " << proof.h.fri_root_count << "\n";
        std::cout << "fri_query_count: " << proof.h.fri_query_count << "\n";
        std::cout << "transition_ratio: " << hex64(proof.h.transition_ratio) << "\n";
        std::cout << "composition_alpha: " << hex64(proof.h.alpha) << "\n";
        std::cout << "public_input_binding: PASS\n";
        std::cout << "statement_digest: PASS\n";
        std::cout << "trace_openings: PASS\n";
        std::cout << "quotient_fri_check: PASS\n";
        std::cout << "local_air_checks: PASS\n";
        std::cout << "quotient_relation_checks: PASS\n";
        print_digest("trace_root", proof.trace_root.data());
        print_digest("quotient_root", quotient_root);
        print_digest("final_root", final_root);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "QINGMING-STARK-G64 verifier\n";
        std::cerr << "status: FAIL\n";
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
