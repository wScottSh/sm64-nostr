# Host test tool for the Nostr pipeline (spec #24, sub-issues #25, #26, and #27).
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
#
# Sub-issue #27 adds the QR encode/decode round-trip test. qrcodegen.c and
# qr_adapter.c are the SAME pure pipeline sources as the ROM side (see the
# root Makefile's PIPELINE_C99_PORT_SRC/PIPELINE_ROM_OBJS). qr_host_decode.c
# is different: it is a HOST-ONLY QR bitmap decoder (structural, driven by
# the same qrcodegen layout constants -- see its own header comment) that
# deliberately lives here under tools/pipeline_test, NOT under
# src/pipeline/, so it can never be pulled into the ROM's object graph --
# the ROM never needs to decode a QR Code, only render one (#32, out of
# scope here).
#
# Sub-issue #28 adds sha256.c and event_id.c -- again the SAME pure pipeline
# sources as the ROM side (PIPELINE_C99_PORT_SRC/PIPELINE_ROM_OBJS) -- plus
# SHA-256 KATs, the canonical-serialization id-equals-reference assertion,
# and the content-escaping-path assertion in main.c. These reuse the SAME
# generated event_profile.h (TEST_PRIVKEY_HEX/TEST_CREATED_AT above) already
# built for test_pubkey_known_answer, so the baked serialization prefix used
# by the reference oracle (tools/reference_event_id.js, host/test-only,
# never a ROM path) and by the pipeline's own id computation are guaranteed
# to agree.
#
# Sub-issue #29 adds secp256k1.c and schnorr_adapter.c -- again the SAME
# pure pipeline sources as the ROM side -- plus the BIP-340 signing KAT
# (privkey = TEST_PRIVKEY_HEX = the published BIP-340 test vector 0 key,
# aux_rand = 0), an internal sign-then-verify self-consistency check, and a
# tampered-message-is-rejected check, all in main.c. The signature this KAT
# pins was independently cross-checked against @noble/curves (a real,
# separately-maintained JS secp256k1/Schnorr library) -- see
# tools/verify_schnorr_reference.js (host/test-only, like
# reference_event_id.js, never a ROM path) -- which is the GENUINELY
# independent verifier spec #24/#29's acceptance criteria call for;
# pipeline_schnorr_verify() in this host tool is only an internal
# self-consistency check, not that independent oracle.
#
# Sub-issue #31 adds capture.c -- the pure capture-glue half (field
# extraction + content-nonce hashing, see capture.h) called both by the
# ROM's real capture glue at interact_star_or_key (src/game/interaction.c)
# and, here, by main.c's test_capture_matches_host_build_event(), which
# feeds it fixed capture-time inputs and asserts the resulting build_event()
# bytes are byte-identical to a StarCapture built directly. Since both
# paths call the SAME pipeline_capture_build() and the SAME build_event(),
# byte-identity holds by construction rather than by executing the ROM.

CC           := gcc
PYTHON       := python3
PIPELINE_DIR := ../../src/pipeline
TOOLS_DIR    := ..
BUILD_DIR    := build
INC_DIR      := $(BUILD_DIR)/include

CFLAGS := -std=gnu99 -Wall -Wextra -I $(PIPELINE_DIR) -I $(INC_DIR)

SRCS := main.c $(PIPELINE_DIR)/build_event.c $(PIPELINE_DIR)/port_stub_c99.c $(PIPELINE_DIR)/pack_adapter.c \
        $(PIPELINE_DIR)/qrcodegen.c $(PIPELINE_DIR)/qr_adapter.c qr_host_decode.c \
        $(PIPELINE_DIR)/sha256.c $(PIPELINE_DIR)/event_id.c \
        $(PIPELINE_DIR)/secp256k1.c $(PIPELINE_DIR)/schnorr_adapter.c \
        $(PIPELINE_DIR)/capture.c
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
