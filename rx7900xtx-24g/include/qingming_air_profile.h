// SPDX-License-Identifier: Apache-2.0
#ifndef QINGMING_AIR_PROFILE_H
#define QINGMING_AIR_PROFILE_H

#include <stdint.h>

/*
  Public AIR profile metadata.

  Current compiled AIR profile:

    QINGMING-AIR-GEOCLOCK-G64

  public_inputs[0] = transition_ratio

  constraint:
    trace_next - transition_ratio * trace_current = 0

  This header is protocol metadata only. It is not a C ABI.
*/

#define QINGMING_AIR_PROFILE_GEOCLOCK_G64 1u

#endif
