# SPDX-License-Identifier: Apache-2.0
HIPCC ?= hipcc
CXX ?= g++

HIPFLAGS ?= -O3 -std=c++17 -Iinclude
CXXFLAGS ?= -O3 -std=c++17 -Iinclude

BUILD_DIR := build

BACKEND := $(BUILD_DIR)/qingming_stark_g64_backend
VERIFIER := $(BUILD_DIR)/qingming_stark_g64_verifier

.PHONY: all clean dirs

all: dirs $(BACKEND) $(VERIFIER)

dirs:
	mkdir -p $(BUILD_DIR)

$(BACKEND): src/qingming_stark_g64_backend.hip include/qingming_poseidon2_g64_constants.h | dirs
	$(HIPCC) $(HIPFLAGS) $< -o $@

$(VERIFIER): src/qingming_stark_g64_verifier.cpp | dirs
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -rf $(BUILD_DIR)
