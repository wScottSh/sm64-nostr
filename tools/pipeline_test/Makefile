# Host test tool for the Nostr pipeline (spec #24, sub-issues #25 and #26).
#
# Links the SAME pure pipeline sources compiled into the ROM
# (../../src/pipeline/*.c) a second time, unmodified, into a native host
# binary. This is the second "adapter" that proves the pipeline's
# interface -- build_event() -- is a real, exercised seam, mirroring the
# tools/asm-processor/tests prior art for a host tool with its own runner.
#
# port_stub_c99.c requires C99 (see its own header comment, and the root
# Makefile's per-object carve-out for the ROM side); on the host side there
# is no COMPILER=ido concern, so the whole tool is just built with -std=gnu99.
#
# Sub-issue #26 adds two generated headers, built here from the identical
# sources the root Makefile uses for the ROM side -- never copied, never
# hand-duplicated:
#   - format_descriptor.h: rendered from ../format_descriptor.json by
#     ../gen_format_descriptor.py. Same JSON, same generator, as the ROM
#     side -- this IS the single-source-of-truth wiring the format
#     descriptor exists to prove.
#   - event_profile.h: rendered by ../gen_event_profile.py, but from a
#     FIXED KAT private key (not the real per-event secret in keys/, which
#     this host tool must never read) -- see TEST_PRIVKEY below. This lets
#     the host tool assert the derived pubkey against a known-answer vector.

CC           := gcc
PYTHON       := python3
PIPELINE_DIR := ../../src/pipeline
TOOLS_DIR    := ..
BUILD_DIR    := build
INC_DIR      := $(BUILD_DIR)/include

CFLAGS := -std=gnu99 -Wall -Wextra -I $(PIPELINE_DIR) -I $(INC_DIR)

SRCS := main.c $(PIPELINE_DIR)/build_event.c $(PIPELINE_DIR)/port_stub_c99.c $(PIPELINE_DIR)/pack_adapter.c
BIN  := pipeline_test

# BIP-340 test vector 0 (privkey=3): a fixed, published known-answer key,
# never used for anything real. Deliberately NOT read from keys/ -- this
# tool must never touch the real per-event secret.
TEST_PRIVKEY_HEX  := 0000000000000000000000000000000000000000000000000000000000000003
TEST_PRIVKEY_FILE := $(BUILD_DIR)/test_privkey.hex
TEST_CREATED_AT   := 1700000000

FORMAT_DESCRIPTOR_JSON := $(PIPELINE_DIR)/format_descriptor.json
FORMAT_DESCRIPTOR_H    := $(INC_DIR)/format_descriptor.h
EVENT_PROFILE_H_IN     := ../../include/event_profile.h.in
EVENT_PROFILE_H        := $(INC_DIR)/event_profile.h
REGISTRY_FILE          := $(BUILD_DIR)/registry.md

.PHONY: all test clean

all: test

$(TEST_PRIVKEY_FILE):
	@mkdir -p $(BUILD_DIR)
	@echo $(TEST_PRIVKEY_HEX) > $@

$(FORMAT_DESCRIPTOR_H): $(FORMAT_DESCRIPTOR_JSON) $(TOOLS_DIR)/gen_format_descriptor.py
	@mkdir -p $(INC_DIR)
	$(PYTHON) $(TOOLS_DIR)/gen_format_descriptor.py --json $(FORMAT_DESCRIPTOR_JSON) --out $@

$(EVENT_PROFILE_H): $(EVENT_PROFILE_H_IN) $(TEST_PRIVKEY_FILE) $(TOOLS_DIR)/gen_event_profile.py $(TOOLS_DIR)/nostr_secp256k1.py
	@mkdir -p $(INC_DIR)
	$(PYTHON) $(TOOLS_DIR)/gen_event_profile.py --privkey $(TEST_PRIVKEY_FILE) --template $(EVENT_PROFILE_H_IN) --out $@ --label host-kat --registry $(REGISTRY_FILE) --commit host-test --created-at $(TEST_CREATED_AT)

$(BIN): $(SRCS) $(FORMAT_DESCRIPTOR_H) $(EVENT_PROFILE_H)
	$(CC) $(CFLAGS) -o $@ $(SRCS)

test: $(BIN)
	./$(BIN)

clean:
	$(RM) -r $(BIN) $(BUILD_DIR)
