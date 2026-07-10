// SPDX-License-Identifier: Apache-2.0
#ifndef QINGMING_PROOF_FORMAT_H
#define QINGMING_PROOF_FORMAT_H

#include <stdint.h>

/*
  QSPG64 full STARK proof metadata.

  .qsp = QSPG64 full STARK proof.

  QSPG64 contains:
    public input binding
    statement digest binding
    trace_root
    quotient_root
    QMPG64 quotient-FRI proof core
    trace openings
    local AIR verifier material

  This header is protocol metadata only. It is not a C ABI.
*/

#define QINGMING_G64_DIGEST_WORDS 4u
#define QINGMING_G64_FIELD_BYTES 8u
#define QINGMING_FRI_QUERY_COUNT 32u

typedef struct qingming_digest_g64 {
    uint64_t words[QINGMING_G64_DIGEST_WORDS];
} qingming_digest_g64;

typedef struct qingming_proof_roots {
    qingming_digest_g64 trace_root;
    qingming_digest_g64 quotient_root;
    qingming_digest_g64 final_root;
} qingming_proof_roots;

#endif
