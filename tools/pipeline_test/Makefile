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
#
# Sub-issue #32 adds ../../src/game/qr_render.c -- the renderer glue's PURE
# pixel-placement core (see src/game/qr_render.h). This is the SAME source
# the ROM build compiles from src/game (one of the Makefile's own SRC_DIRS),
# unmodified, mirroring how src/pipeline/*.c is already compiled twice.
# main.c's test_qr_render_blit_round_trips_through_decode() renders a real
# build_event() qr_bitmap into an in-memory RGBA16 buffer via
# qr_render_blit_qr_at() (issue #84's overlay redesign; the pure core also
# adds qr_render_layout()/qr_render_overlay_rgba16()), reconstructs the grid
# by reading pixels
# back out of that buffer (reversing the fixed scale + quiet zone), packs
# that reconstructed grid into a qrcodegen-format buffer, and feeds it to
# the existing qr_host_decode() -- asserting the decoded bytes equal
# build_event()'s own packed_payload exactly. This proves the blit is
# faithful without an emulator/camera. GAME_DIR/-I below only ever reaches
# qr_render.c/.h and (sub-issue #33) qr_display.c/.h -- never qr_render_n64.c/
# .h or qr_display_n64.c/.h, which include <ultra64.h> and so are
# deliberately excluded from this host build (see qr_render_n64.h's and
# qr_display_n64.h's own header comments).

# Sub-issue #33 adds ../../src/game/qr_display.c -- the shared qr_display
# state machine's PURE core (debounced-A dismiss, one-shot erase, never-
# re-summonable latch). Compiled here unmodified, exactly like qr_render.c;
# qr_display_n64.c (the real-controller/real-renderer/real-time-stop N64
# shell) is deliberately excluded for the same <ultra64.h> reason
# qr_render_n64.c already is.
#
# Spec #43 sub-issue #44 (fast field mod-p reduction) adds no new source
# files -- secp256k1.c/.h are the SAME files, rewritten in place -- but
# does add -DPIPELINE_SECP256K1_OP_COUNT below, plus main.c's field-multiply
# differential sweep and op-count-proxy tests.
#
# Spec #43 sub-issue #46 (build-time public point) adds a third generated
# header, secp256k1_baked.h: rendered by ../gen_secp256k1_baked.py from the
# SAME fixed TEST_PRIVKEY_HEX below (never the real per-event secret --
# same rule as EVENT_PROFILE_H's own comment above), mirroring how
# EVENT_PROFILE_H is built here from that key. schnorr_adapter.c now
# #includes this generated header instead of computing P = d*G at runtime;
# main.c's differential-sweep test confirms the baked P matches a
# reference-computed d*G for TEST_PRIVKEY_HEX.
#
# Spec #75 sub-issue #76 (--event-name build input) makes ../gen_event_
# profile.py's --event-name REQUIRED (no default, mirroring the privkey
# fail-closed discipline), so EVENT_PROFILE_H's recipe below now always
# passes a fixed, in-charset, KAT-style value -- this host tool has no HUD
# to render the name on, so the value itself is arbitrary, but the flag
# must be present or gen_event_profile.py now refuses to run.
#
# Spec #91 sub-issue #126 raises the event-name cap 15->20 chars, coupled
# across gen_event_profile.py's EVENT_NAME_MAX_LEN, format_descriptor.json's
# NAME.max_size, and this worst-case fixture's own WORSTCASE_EVENT_NAME
# (below) -- ADR-0006's multi-frame transport means there is no combined
# single-QR-frame ceiling to re-check; the +5 B just yields a (possibly)
# larger PIPELINE_BUILT_FRAME_COUNT, still whatever build_event.c computes.
# Spec #90 sub-issue #139 SHRINKS this cap back 20->17 chars, SUPERSEDING
# #126 (the same three sites move together again, now down by 3 B).
#
# Spec #109 sub-issue #111 promotes the event name to a signed on-wire tag,
# packed onto the wire alongside the per-game tag. Prior to ADR-0006's
# multi-frame transport (spec #115, sub-issue #117), both fields shared the
# SAME v7-MEDIUM single-QR-symbol budget (PIPELINE_QR_MAX_PAYLOAD_BYTES,
# 122 B), which is why the fixture value below was shortened from the
# pre-#111 "HOST TEST" (9 B) to "TEST" (4 B) -- that combined single-frame
# ceiling is now retired (build_event.c's fits-QR compile-time check is
# gone; a longer tag+name combination just emits more frames), so "TEST"
# stays purely a small, readable host-test fixture choice, not a
# ceiling-driven one.
#
# Spec #115 sub-issue #118 adds ../../src/game/qr_cycle.c -- the star-
# capture overlay's frame-cycling PURE core (the (frameCount, tick) ->
# frameIndex selector). Compiled here unmodified, exactly like qr_render.c/
# qr_display.c above; the N64 shell half (qr_display_n64.c's cycling glue)
# is deliberately excluded for the same <ultra64.h> reason qr_render_n64.c/
# qr_display_n64.c already are.
#
# Spec #115 sub-issue #117 adds a SECOND, separate binary (WORSTCASE_BIN,
# worst_case_main.c) built against its own generated event_profile.h, baked
# with format v3's actual worst-case field widths (WORSTCASE_TAG, 10 B;
# WORSTCASE_EVENT_NAME, 17 B as of spec #90 sub-issue #139, superseding
# #126's 20 B) instead of this file's own small "sm64"/"TEST" fixture --
# see worst_case_main.c's own header comment for why this has to be a
# separate binary
# (PIPELINE_BUILT_PAYLOAD_SIZE/_FRAME_COUNT are
# fixed compile-time constants per binary, derived from whichever ONE
# event_profile.h it links) and why this build existing and compiling at
# all is the sub-issue #117 regression lock.

CC           := gcc
PYTHON       := python3
SRC_DIR      := ../../src
PIPELINE_DIR := ../../src/pipeline
GAME_DIR     := ../../src/game
TOOLS_DIR    := ..
BUILD_DIR    := build
INC_DIR      := $(BUILD_DIR)/include

# -I $(SRC_DIR) mirrors the ROM build's own INCLUDE_DIRS (which includes
# plain "src"): qr_render.h's #include "pipeline/qr_adapter.h" is written
# relative to src/, exactly like src/game/interaction.c's own
# #include "pipeline/build_event.h" (spec #24, sub-issue #31) -- so it must
# resolve identically here.
# -DPIPELINE_SECP256K1_OP_COUNT (spec #43 sub-issue #44): turns on
# secp256k1.c's host-side field-multiply/operation-count proxy counters,
# host-test-tool-only -- the ROM build's PIPELINE_C99_CFLAGS in the root
# Makefile deliberately never defines this, so the counters (and their
# per-limb-operation increments on the signing hot path) compile to
# nothing there. See secp256k1.h's own header comment on
# pipeline_secp256k1_reset_op_count/_get_op_count.
CFLAGS := -std=gnu99 -Wall -Wextra -DPIPELINE_SECP256K1_OP_COUNT -I $(SRC_DIR) -I $(PIPELINE_DIR) -I $(GAME_DIR) -I $(INC_DIR)

SRCS := main.c $(PIPELINE_DIR)/build_event.c $(PIPELINE_DIR)/port_stub_c99.c $(PIPELINE_DIR)/pack_adapter.c \
        $(PIPELINE_DIR)/qrcodegen.c $(PIPELINE_DIR)/qr_adapter.c qr_host_decode.c \
        $(PIPELINE_DIR)/sha256.c $(PIPELINE_DIR)/event_id.c \
        $(PIPELINE_DIR)/secp256k1.c $(PIPELINE_DIR)/schnorr_adapter.c \
        $(PIPELINE_DIR)/capture.c $(GAME_DIR)/qr_render.c $(GAME_DIR)/qr_display.c \
        $(GAME_DIR)/qr_cycle.c \
        $(PIPELINE_DIR)/base32.c $(PIPELINE_DIR)/fragment.c $(PIPELINE_DIR)/url.c
BIN  := pipeline_test

# BIP-340 test vector 0 (privkey=3): a fixed, published known-answer key,
# never used for anything real. Deliberately NOT read from keys/ -- this
# tool must never touch the real per-event secret.
TEST_PRIVKEY_HEX  := 0000000000000000000000000000000000000000000000000000000000000003
TEST_PRIVKEY_FILE := $(BUILD_DIR)/test_privkey.hex
TEST_CREATED_AT   := 1700000000

# Airgap transport base URL, per #101's ratified <BASE>#<SEQ>/<TOTAL>/<PAYLOAD>
# template (spec #115 sub-issue #116, realigned by spec #122 sub-issue
# #123): deliberately MIXED-case (unlike the root Makefile's own
# all-lowercase dev default) so this host tool's own KAT/round-trip tests
# directly exercise the verbatim-base contract -- a build whose base
# contains uppercase AND lowercase bytes must round-trip with neither
# folded, proving build_event()/url.h never mangle case. This host tool's
# baked BuiltEvent (PIPELINE_BUILT_PAYLOAD_SIZE 121 B, "sm64" tag + "TEST"
# name) still exercises a realistic multi-frame split (N=2) at the real
# build_event() seam -- see main.c's test_build_event_multiframe_
# round_trip() for why: ADR-0006 itself observes the honest v3 floor
# already overflows one frame once URL-wrapped under any realistic domain,
# so this build's own N is expected to be >1, not a hand-picked worst case.
TEST_URL_BASE     := https://Sm64Nostr.Pages.Dev

FORMAT_DESCRIPTOR_JSON := $(PIPELINE_DIR)/format_descriptor.json
FORMAT_DESCRIPTOR_H    := $(INC_DIR)/format_descriptor.h
EVENT_PROFILE_H_IN     := ../../include/event_profile.h.in
EVENT_PROFILE_H        := $(INC_DIR)/event_profile.h
EVENT_MANIFEST         := $(BUILD_DIR)/event_profile.manifest.json
SECP256K1_BAKED_H_IN   := ../../include/secp256k1_baked.h.in
SECP256K1_BAKED_H      := $(INC_DIR)/secp256k1_baked.h

# Worst-case tag+name fixture (spec #115, sub-issue #117; NAME cap raised
# 15->20, spec #91 sub-issue #126; SHRUNK BACK 20->17, spec #90 sub-issue
# #139, which SUPERSEDES #126): format v3's own actual per-field maxima
# (format_descriptor.json's TAG.max_size == 10,
# gen_event_profile.py's EVENT_NAME_MAX_LEN == 17) -- the exact combination
# that used to overflow the now-removed single-QR-frame total-payload
# ceiling. A SEPARATE build dir/binary from the main pipeline_test above
# (see worst_case_main.c's own header comment for why).
WORSTCASE_TAG                  := 0123456789
WORSTCASE_EVENT_NAME           := ABCDEFGHIJKLMNOPQ
WORSTCASE_BUILD_DIR            := build-worstcase
WORSTCASE_INC_DIR              := $(WORSTCASE_BUILD_DIR)/include
WORSTCASE_EVENT_PROFILE_H      := $(WORSTCASE_INC_DIR)/event_profile.h
WORSTCASE_FORMAT_DESCRIPTOR_H  := $(WORSTCASE_INC_DIR)/format_descriptor.h
WORSTCASE_SECP256K1_BAKED_H    := $(WORSTCASE_INC_DIR)/secp256k1_baked.h
WORSTCASE_MANIFEST             := $(WORSTCASE_BUILD_DIR)/event_profile.manifest.json
WORSTCASE_SRCS := worst_case_main.c $(PIPELINE_DIR)/build_event.c $(PIPELINE_DIR)/port_stub_c99.c \
        $(PIPELINE_DIR)/pack_adapter.c $(PIPELINE_DIR)/qrcodegen.c $(PIPELINE_DIR)/qr_adapter.c \
        $(PIPELINE_DIR)/sha256.c $(PIPELINE_DIR)/event_id.c \
        $(PIPELINE_DIR)/secp256k1.c $(PIPELINE_DIR)/schnorr_adapter.c \
        $(PIPELINE_DIR)/base32.c $(PIPELINE_DIR)/fragment.c $(PIPELINE_DIR)/url.c
# No -DPIPELINE_SECP256K1_OP_COUNT here (unlike CFLAGS above): worst_case_main.c
# never reads the op-count proxy counters, so this binary has no use for them.
WORSTCASE_CFLAGS := -std=gnu99 -Wall -Wextra -I $(SRC_DIR) -I $(PIPELINE_DIR) -I $(WORSTCASE_INC_DIR)
WORSTCASE_BIN := pipeline_test_worstcase

# Spec #115 sub-issue #119 (the reader page) adds gen_reader_fixture.c and
# this target: a host-only program (never a ROM path, mirrors
# tools/reference_event_id.js/fixtures/gen_live_vectors.mjs) that dumps a
# real build_event() call's actual emitted QR frames (full <BASE>#<SEQ>/<TOTAL>/
# <PAYLOAD> URL text, structurally decoded via qr_host_decode_mixed -- the
# same two-segment decoder the multiframe round-trip test above uses) to
# reader/test/fixtures/multiframe_fixture.json,
# the reader page's own reassembly/decode/id-recompute test fixture. Reuses
# this Makefile's own $(FORMAT_DESCRIPTOR_H)/$(EVENT_PROFILE_H) (same
# privkey=3/tag "sm64"/name "TEST"/url-base TEST_URL_BASE baked profile
# main.c's test_build_event_end_to_end() already pins its own oracle values
# against) so the fixture and that test describe the identical build_event()
# call. gen_reader_fixture.c self-checks (recomputes id from unpacked wire
# fields, verifies the unpacked sig against it) before printing anything, so
# a fixture whose id/sig don't verify can never be written.
READER_FIXTURE_SRCS := gen_reader_fixture.c $(PIPELINE_DIR)/build_event.c $(PIPELINE_DIR)/port_stub_c99.c \
        $(PIPELINE_DIR)/pack_adapter.c $(PIPELINE_DIR)/qrcodegen.c $(PIPELINE_DIR)/qr_adapter.c qr_host_decode.c \
        $(PIPELINE_DIR)/sha256.c $(PIPELINE_DIR)/event_id.c \
        $(PIPELINE_DIR)/secp256k1.c $(PIPELINE_DIR)/schnorr_adapter.c \
        $(PIPELINE_DIR)/base32.c $(PIPELINE_DIR)/fragment.c $(PIPELINE_DIR)/url.c
READER_FIXTURE_BIN := gen_reader_fixture
READER_FIXTURE_OUT := ../../reader/test/fixtures/multiframe_fixture.json

$(READER_FIXTURE_BIN): $(READER_FIXTURE_SRCS) $(FORMAT_DESCRIPTOR_H) $(EVENT_PROFILE_H) $(SECP256K1_BAKED_H)
	$(CC) $(CFLAGS) -o $@ $(READER_FIXTURE_SRCS)

reader-fixture: $(READER_FIXTURE_BIN)
	@mkdir -p $(dir $(READER_FIXTURE_OUT))
	./$(READER_FIXTURE_BIN) > $(READER_FIXTURE_OUT)

.PHONY: all test worstcase-test reader-fixture clean

all: test worstcase-test

$(TEST_PRIVKEY_FILE):
	@mkdir -p $(BUILD_DIR)
	@echo $(TEST_PRIVKEY_HEX) > $@

$(FORMAT_DESCRIPTOR_H): $(FORMAT_DESCRIPTOR_JSON) $(TOOLS_DIR)/gen_format_descriptor.py
	@mkdir -p $(INC_DIR)
	$(PYTHON) $(TOOLS_DIR)/gen_format_descriptor.py --json $(FORMAT_DESCRIPTOR_JSON) --out $@

$(EVENT_PROFILE_H): $(EVENT_PROFILE_H_IN) $(TEST_PRIVKEY_FILE) $(TOOLS_DIR)/gen_event_profile.py $(TOOLS_DIR)/nostr_secp256k1.py
	@mkdir -p $(INC_DIR)
	$(PYTHON) $(TOOLS_DIR)/gen_event_profile.py --privkey $(TEST_PRIVKEY_FILE) --template $(EVENT_PROFILE_H_IN) --out $@ --label host-kat --manifest $(EVENT_MANIFEST) --commit host-test --created-at $(TEST_CREATED_AT) --event-name "TEST" --url-base "$(TEST_URL_BASE)"

$(SECP256K1_BAKED_H): $(SECP256K1_BAKED_H_IN) $(TEST_PRIVKEY_FILE) $(TOOLS_DIR)/gen_secp256k1_baked.py $(TOOLS_DIR)/nostr_secp256k1.py
	@mkdir -p $(INC_DIR)
	$(PYTHON) $(TOOLS_DIR)/gen_secp256k1_baked.py --privkey $(TEST_PRIVKEY_FILE) --template $(SECP256K1_BAKED_H_IN) --out $@

$(BIN): $(SRCS) $(FORMAT_DESCRIPTOR_H) $(EVENT_PROFILE_H) $(SECP256K1_BAKED_H)
	$(CC) $(CFLAGS) -o $@ $(SRCS)

test: $(BIN)
	./$(BIN)

$(WORSTCASE_FORMAT_DESCRIPTOR_H): $(FORMAT_DESCRIPTOR_JSON) $(TOOLS_DIR)/gen_format_descriptor.py
	@mkdir -p $(WORSTCASE_INC_DIR)
	$(PYTHON) $(TOOLS_DIR)/gen_format_descriptor.py --json $(FORMAT_DESCRIPTOR_JSON) --out $@

$(WORSTCASE_EVENT_PROFILE_H): $(EVENT_PROFILE_H_IN) $(TEST_PRIVKEY_FILE) $(TOOLS_DIR)/gen_event_profile.py $(TOOLS_DIR)/nostr_secp256k1.py
	@mkdir -p $(WORSTCASE_INC_DIR)
	$(PYTHON) $(TOOLS_DIR)/gen_event_profile.py --privkey $(TEST_PRIVKEY_FILE) --template $(EVENT_PROFILE_H_IN) --out $@ --label host-kat-worstcase --manifest $(WORSTCASE_MANIFEST) --commit host-test --created-at $(TEST_CREATED_AT) --event-name "$(WORSTCASE_EVENT_NAME)" --tag "$(WORSTCASE_TAG)" --url-base "$(TEST_URL_BASE)"

$(WORSTCASE_SECP256K1_BAKED_H): $(SECP256K1_BAKED_H_IN) $(TEST_PRIVKEY_FILE) $(TOOLS_DIR)/gen_secp256k1_baked.py $(TOOLS_DIR)/nostr_secp256k1.py
	@mkdir -p $(WORSTCASE_INC_DIR)
	$(PYTHON) $(TOOLS_DIR)/gen_secp256k1_baked.py --privkey $(TEST_PRIVKEY_FILE) --template $(SECP256K1_BAKED_H_IN) --out $@

$(WORSTCASE_BIN): $(WORSTCASE_SRCS) $(WORSTCASE_FORMAT_DESCRIPTOR_H) $(WORSTCASE_EVENT_PROFILE_H) $(WORSTCASE_SECP256K1_BAKED_H)
	$(CC) $(WORSTCASE_CFLAGS) -o $@ $(WORSTCASE_SRCS)

worstcase-test: $(WORSTCASE_BIN)
	./$(WORSTCASE_BIN)

clean:
	$(RM) -r $(BIN) $(BUILD_DIR) $(WORSTCASE_BIN) $(WORSTCASE_BUILD_DIR) $(READER_FIXTURE_BIN)
