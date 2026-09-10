/*
 * Host test tool for the pipeline (spec #24, sub-issues #25, #26, and #27).
 *
 * #25: feeds a fixed StarCapture + key into build_event() and asserts the
 * stub output is byte-exact -- proving the pure pipeline sources compile
 * and run here identically to how they will in the ROM build.
 *
 * #26 adds:
 *   - a known-answer test for the build-time derived x-only pubkey baked
 *     into the generated event_profile.h (built here from a fixed BIP-340
 *     test vector, never the real per-event secret -- see the Makefile);
 *   - a format-descriptor round-trip/consistency check: pack a StarCapture
 *     + signature via pipeline_pack(), unpack it back via pipeline_unpack(),
 *     and assert both the fields and the descriptor's own size accounting
 *     round-trip exactly -- proving the ROM pack side and this host unpack
 *     side genuinely agree on the wire layout because both are generated
 *     from the same format_descriptor.json.
 *
 * #27 adds the QR encode/decode round-trip and over-budget-rejection
 * tests -- see the comment above test_qr_round_trip_representative_sizes().
 *
 * #28 adds:
 *   - known-answer tests for the ported SHA-256 (sha256.h/.c) against
 *     published FIPS 180-4 / NIST vectors;
 *   - the id-equals-reference assertion: pipeline_event_compute_id()
 *     (event_id.h/.c) against ids independently computed by the real
 *     `nostr-tools` npm package (see tools/reference_event_id.js) for the
 *     same StarCapture + baked event-profile prefix;
 *   - an explicit check that the content double-serialization escaping
 *     (`"` -> `\"`) path is exercised in the serialized byte buffer, not
 *     just implied by opaque id equality.
 *
 * #30 wires the real build_event() (serialize -> id -> sign -> pack -> QR,
 * see build_event.c) and adds the pipeline's first full-interface,
 * end-to-end host test: build_event() for a real StarCapture + the BIP-340
 * KAT privkey, then (a) decode qr_bitmap and assert it equals
 * packed_payload exactly, (b) unpack packed_payload, recompute the id from
 * the rebuilt StarCapture, assert that id matches the same nostr-tools
 * reference id already pinned for vector A in #28, and assert the
 * signature matches an independently-computed BIP-340 signature
 * (@noble/curves oracle, see tools/verify_schnorr_reference.js's
 * conventions) and verifies, and (c) flip one payload content byte and
 * assert verification against the original signature now fails.
 *
 * #31 adds capture.c's tests (src/pipeline/capture.h -- the pure capture-
 * glue half the ROM's real glue at interact_star_or_key also calls, spec
 * #24 sub-issue #31):
 *   - test_capture_build_known_answer(): fixed capture-time inputs (course,
 *     act, coins, frames, starIndex, osCount, globalTimer, rawStickX/Y,
 *     buttonMask) through pipeline_capture_build(), asserting every
 *     StarCapture field lands correctly AND that nonce16 matches a
 *     known-answer value computed with Python's own hashlib (a genuinely
 *     independent SHA-256 implementation, not this repo's ported one) over
 *     the exact same 12-byte big-endian concatenation
 *     (osCount||globalTimer||rawStickX||rawStickY||buttonMask) capture.h's
 *     own contract documents;
 *   - test_capture_matches_host_build_event(): builds a BuiltEvent via
 *     pipeline_capture_build() + build_event() (the SAME two calls the ROM
 *     glue makes) and a second BuiltEvent via a StarCapture constructed by
 *     hand with the identical field values (including that same
 *     known-answer nonce16) + build_event(), then asserts both
 *     packed_payload and qr_bitmap are byte-identical -- the sub-issue #31
 *     acceptance criterion ("the ROM's produced payload for a run is
 *     byte-identical to the host tool's output for the same
 *     course/act/coins/frames/nonce") demonstrated by construction: both
 *     paths call the same pipeline_capture_build()/build_event(), so
 *     identical inputs structurally cannot diverge.
 *
 * #32/#84 add test_qr_render_blit_round_trips_through_decode() (renderer
 * glue, src/game/qr_render.h/.c): renders a real build_event() qr_bitmap
 * into an in-memory plain RGBA16 buffer via the SAME pure
 * qr_render_blit_qr_at() the ROM build compiles (src/game is compiled a
 * second time here, unmodified, exactly like src/pipeline already is), then
 * reconstructs the module grid by sampling the CENTER pixel of every
 * module's scaled block back out of that buffer (reversing the fixed
 * integer scale + quiet zone qr_render.h documents), packs the
 * reconstruction into a qrcodegen-format buffer using the same public
 * bit-packing layout qrcodegen_getModule()/qr_adapter.h's own accessors
 * read (byte 0 = grid size, then row-major bits packed LSB-first per byte
 * starting at byte 1 -- see qrcodegen.c's getModuleBounded()/
 * setModuleBounded()), and feeds that reconstruction to the existing
 * qr_host_decode() -- asserting the decoded bytes equal build_event()'s own
 * packed_payload exactly. Also asserts quiet-zone pixels are exactly
 * QR_RENDER_WHITE_RGBA16 and that the module block size is exactly
 * QR_RENDER_MODULE_SCALE_PX pixels (every pixel in a block matches its
 * module's color, and pixels just outside the block on both axes differ
 * whenever the neighboring module differs) -- proving the blit is faithful
 * without an emulator/camera (spec #24 acceptance criterion #16's spirit).
 *
 * #33 adds test_qr_display_state_machine() (../../src/game/qr_display.h/.c
 * -- the shared qr_display state machine's PURE core, compiled a second
 * time here exactly like qr_render.c already is). Feeds a real
 * build_event() qr_bitmap through a QrDisplayState on synthetic input
 * sequences and asserts the four behaviors sub-issue #33's acceptance
 * criteria hinge on: (a) holding A across present() (the same press that
 * triggered the star dance) never dismisses; (b) release-then-press held
 * for QR_DISPLAY_MIN_HOLD_FRAMES consecutive frames does dismiss; (c) the
 * held bitmap is erased (all-zero) immediately after that dismissal; (d) a
 * present() attempt on that same, already-dismissed state is rejected (the
 * never-re-summonable invariant). The N64-specific pump (real controller
 * input, the real renderer, real time-stop coordination -- qr_display_n64.h/
 * .c) is deliberately NOT compiled here: it includes <ultra64.h> and is
 * exercised only on emulator (see this branch's own PR notes for what must
 * be verified there: both save flows replaced, a debounced A dismiss, and
 * memory erased).
 *
 * Spec #43 sub-issue #44 (fast field mod-p reduction, the first slice of
 * spec #43's pure performance rewrite of this pipeline's secp256k1
 * internals -- see that spec's own issue text for the full staged plan)
 * adds test_field_mul_differential_sweep() and test_field_op_count_proxy()
 * (secp256k1.h/.c, near the bottom of this file). All tests above this
 * point are the pre-existing regression net #44's acceptance criteria
 * require to stay green, byte-for-byte, through the rewrite -- none of
 * their expected-byte literals changed. The two new tests are this
 * sub-issue's own proof mechanisms: a seeded differential sweep of the new
 * fast field multiply (pipeline_secp256k1_fe_mul_fast) against the
 * retained naive-reduction reference (pipeline_secp256k1_fe_mul_reference)
 * over random 256-bit operand pairs plus a handful of pinned edge vectors,
 * and a host-side field-multiply/operation-count proxy
 * (pipeline_secp256k1_reset_op_count/_get_op_count) showing the fast path
 * does dramatically less primitive word-level work than the naive one --
 * NOT a wall-clock timing comparison, which wouldn't represent the target
 * VR4300.
 *
 * Spec #43 sub-issue #45 (fast scalar mod-n reduction, the second slice)
 * adds test_scalar_differential_sweep() (reusing the same seeded-PRNG/
 * differential-check-one/pinned-edge-vectors shape #44 established, just
 * against pipeline_secp256k1_scalar_reduce_fast/_reference and
 * pipeline_secp256k1_scalar_mul_fast/_reference instead of the field
 * equivalents) and extends test_field_op_count_proxy() with an explicit
 * scalar-path fast-vs-naive op-count comparison, plus tightens that
 * function's own per-signature op-count bound now that the scalar path
 * (previously still generic/untouched by #44) is fast too.
 *
 * Spec #109 sub-issue #110 (format v3's second variable-length field, NAME)
 * bumps FORMAT_TAG to 0x03 and adds NAME_LEN/NAME (mirroring TAG_LEN/TAG)
 * ahead of SIG: pipeline_pack()/pipeline_unpack() gain a name buffer +
 * length parameter pair, test_pipeline_pack_unpack_name_round_trip() adds
 * the dedicated event-name pack/unpack round-trip, and every existing
 * pipeline_pack()/pipeline_unpack() call site (test_format_descriptor_round_trip,
 * test_build_event_end_to_end, test_pipeline_unpack_boundary_and_rejections)
 * is updated for the new signature and format v3's larger PIPELINE_FMT_FIXED_SIZE.
 * test_live_wire_vectors_round_trip() now asserts REJECTION of its frozen
 * real-device format-v2 captures (FORMAT_TAG 0x02) -- #110's own explicit
 * acceptance criterion -- rather than acceptance; see that test's own
 * updated header comment.
 *
 * Spec #109 sub-issue #111 threads the real baked event name
 * (PIPELINE_EVENT_NAME, "TEST" for this host tool -- see the Makefile's own
 * comment) into both the signed serialization (event_id.c's
 * pipeline_event_serialize(), a third tag ["n","TEST"]) and build_event()'s
 * pack call (PIPELINE_BUILT_PAYLOAD_SIZE grows from 117 to 121 B). Every
 * id/sig oracle value derived from the baked profile -- kExpectedIdA/B/C,
 * kBuildEventExpectedIdA, kBuildEventExpectedSig, and the pinned
 * expectedSerialized string in test_content_escaping_path() -- was
 * re-derived against tools/reference_event_id.js/
 * tools/verify_schnorr_reference.js for the new three-tag serialization
 * (see those scripts' own updated header comments); test_build_event_
 * end_to_end()'s unpacked-name assertion now expects the real baked name,
 * not a zero-length placeholder.
 */
#include <stdio.h>
#include <string.h>

#include "build_event.h"
#include "pack_adapter.h"
#include "event_profile.h"
#include "qr_adapter.h"
#include "qr_host_decode.h"
#include "sha256.h"
#include "event_id.h"
#include "schnorr_adapter.h"
#include "secp256k1.h"
#include "secp256k1_baked.h"
#include "capture.h"
#include "qr_render.h"
#include "qr_display.h"
#include "base32.h"
#include "fragment.h"
#include "url.h"
#include "fixtures/live_vectors.h"

static int g_failures = 0;

static void check(int ok, const char *what)
{
    if (ok) {
        printf("PASS: %s\n", what);
    } else {
        printf("FAIL: %s\n", what);
        g_failures++;
    }
}

/*
 * reassemble_built_event: the "opened webpage" half of ADR-0006's transport
 * (spec #115, sub-issue #116), exercised at the HOST level for this host
 * tool's own baked BuiltEvent shape (PIPELINE_BUILT_FRAME_COUNT frames,
 * PIPELINE_URL_BASE base URL). For each of useCount frame indices named by
 * frameOrder[] (or natural order 0..useCount-1 if frameOrder is NULL):
 * decodes the QR (qr_host_decode_alphanumeric), strips the known base URL
 * (pipeline_url_strip), parses the fragment header (pipeline_fragment_
 * parse_header), and copies its chunk into base32Text at the header's own
 * index -- so frames can be fed in ANY order and still land correctly.
 * Returns nonzero (true) and de-base32's the reassembled text into
 * rawOut/*rawLenOut ONLY if every index 0..PIPELINE_BUILT_FRAME_COUNT-1 was
 * seen at least once; returns 0 (false) -- writing nothing to rawOut -- if
 * any frame fails to decode/strip/parse, or the set is incomplete (a
 * missing fragment reports incomplete, never a wrong/partial event, per
 * spec #115's own acceptance criterion).
 */
static int reassemble_built_event(const BuiltEvent *event, const int *frameOrder, pipeline_u32 useCount,
                                   pipeline_u8 *rawOut, pipeline_u32 rawCap, pipeline_u32 *rawLenOut)
{
    static const pipeline_u8 kUrlBase[] = PIPELINE_URL_BASE;
    pipeline_u8 base32Text[PIPELINE_BUILT_BASE32_LEN];
    int seen[PIPELINE_BUILT_FRAME_COUNT];
    pipeline_u32 seenCount;
    pipeline_u32 i;

    seenCount = 0;
    for (i = 0; i < (pipeline_u32)PIPELINE_BUILT_FRAME_COUNT; i++) {
        seen[i] = 0;
    }

    for (i = 0; i < useCount; i++) {
        int frameIdx = frameOrder ? frameOrder[i] : (int)i;
        unsigned char urlText[PIPELINE_BUILT_URL_MAX_LEN];
        int urlTextLen = -1;
        pipeline_u8 fragment[PIPELINE_BUILT_URL_MAX_LEN];
        pipeline_u32 fragmentLen;
        pipeline_u32 idx, cnt;

        if (frameIdx < 0 || frameIdx >= (int)PIPELINE_BUILT_FRAME_COUNT) {
            return 0;
        }
        if (!qr_host_decode_alphanumeric(event->qr_bitmaps[frameIdx], urlText,
                                          (int)sizeof(urlText), &urlTextLen)) {
            return 0;
        }
        if (!pipeline_url_strip((const pipeline_u8 *)urlText, (pipeline_u32)urlTextLen,
                                 kUrlBase, (pipeline_u32)PIPELINE_URL_BASE_LEN,
                                 fragment, (pipeline_u32)sizeof(fragment), &fragmentLen)) {
            return 0;
        }
        if (!pipeline_fragment_parse_header(fragment, fragmentLen, &idx, &cnt)) {
            return 0;
        }
        if (cnt != (pipeline_u32)PIPELINE_BUILT_FRAME_COUNT || idx >= cnt) {
            return 0;
        }
        {
            pipeline_u32 chunkCap = (pipeline_u32)PIPELINE_BUILT_FRAGMENT_CHUNK_LEN;
            pipeline_u32 chunkLen = fragmentLen - (pipeline_u32)PIPELINE_FRAGMENT_HEADER_LEN;
            pipeline_u32 dest = idx * chunkCap;
            pipeline_u32 k;

            if (dest + chunkLen > (pipeline_u32)PIPELINE_BUILT_BASE32_LEN) {
                return 0;
            }
            for (k = 0; k < chunkLen; k++) {
                base32Text[dest + k] = fragment[(pipeline_u32)PIPELINE_FRAGMENT_HEADER_LEN + k];
            }
        }
        if (!seen[idx]) {
            seen[idx] = 1;
            seenCount++;
        }
    }

    if (seenCount != (pipeline_u32)PIPELINE_BUILT_FRAME_COUNT) {
        return 0; /* incomplete set -- never guess at the missing bytes */
    }

    return pipeline_base32_decode(base32Text, (pipeline_u32)PIPELINE_BUILT_BASE32_LEN, rawOut, rawCap, rawLenOut);
}

/*
 * build_event() end-to-end host test (spec #24, sub-issue #30; format v2
 * self-contained-reconstruction, spec #52 sub-issue #54).
 *
 * Uses StarCapture "vector A" -- the exact same values as
 * test_event_id_matches_reference()/test_content_escaping_path() above
 * (course=15, act=6, coins=100, frames=0x01020304, nonce16=0xCAFE,
 * keyId=0) -- signed with the BIP-340 KAT privkey (=3, the same key baked
 * into this host tool's generated event_profile.h, TEST_PRIVKEY_HEX in the
 * Makefile), so the expected id (kExpectedIdA there) and pubkey
 * (kExpectedPubkey in test_pubkey_known_answer) are already independently
 * pinned oracle values this test can reuse directly.
 *
 * kBuildEventExpectedSig is the BIP-340 signature of that exact id under
 * privkey 3 / aux_rand 0, independently computed via @noble/curves (the
 * same genuinely-separate library tools/verify_schnorr_reference.js uses)
 * -- NOT re-derived from this repo's own pipeline_schnorr_sign(). This is
 * the "independent verifier convention already in the repo" this sub-issue's
 * task calls for, applied to a dynamic (non-all-zero-message) signature
 * instead of BIP-340's own canned test vector 0.
 *
 * Format v2 (spec #52, sub-issue #54): kBuildEventExpectedIdA/
 * kBuildEventExpectedSig changed from their pre-v2 values because TAG_0
 * changed from "cabinet-leaderboard" to the spec-pinned "ag-lb" (see
 * tools/reference_event_id.js/tools/verify_schnorr_reference.js's own
 * header comments for the re-derivation).
 *
 * Format v3 (spec #109, sub-issue #111): both changed AGAIN because
 * build_event() now folds this host tool's baked PIPELINE_EVENT_NAME
 * ("TEST", tools/pipeline_test/Makefile's --event-name) into a third
 * signed tag, ["n","TEST"] -- see tools/reference_event_id.js/
 * tools/verify_schnorr_reference.js's own updated header comments.
 */
static const pipeline_u8 kBuildEventPrivkey[PIPELINE_KEY_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
};
static const pipeline_u8 kBuildEventExpectedIdA[PIPELINE_EVENT_ID_SIZE] = {
    0x91, 0xff, 0x8d, 0xf5, 0x9c, 0x33, 0x9b, 0xf5, 0xc6, 0x43, 0x75, 0x0c, 0xdb, 0x1c, 0x7e, 0xdf,
    0x99, 0xc4, 0x8a, 0xa9, 0xce, 0x78, 0x79, 0xa2, 0x2c, 0x9a, 0x52, 0xda, 0x7b, 0x84, 0x36, 0x2f,
};
static const pipeline_u8 kBuildEventExpectedSig[PIPELINE_SCHNORR_SIG_SIZE] = {
    0x0f, 0x4b, 0xa8, 0x0a, 0xe3, 0x3f, 0x8e, 0x8e, 0x1b, 0xe4, 0x08, 0x38, 0x7f, 0x0e, 0x8e, 0x23,
    0x3b, 0xa2, 0xc7, 0xb0, 0x79, 0x12, 0x0e, 0x0c, 0x12, 0x86, 0xd9, 0x75, 0x03, 0x75, 0x95, 0x3f,
    0x4f, 0x15, 0x88, 0x75, 0x78, 0xcf, 0x46, 0x93, 0xa3, 0xad, 0x45, 0x46, 0xf8, 0x99, 0xe1, 0x76,
    0xb1, 0x25, 0x39, 0x98, 0xd9, 0xfe, 0xf3, 0xa8, 0xa1, 0x9d, 0xba, 0xf8, 0x67, 0xf5, 0x12, 0xb0,
};

static void test_build_event_end_to_end(void)
{
    StarCapture capture;
    BuiltEvent event;
    int buildOk;
    unsigned char decoded[PIPELINE_BUILT_PAYLOAD_SIZE];
    pipeline_u32 decodedLen = 0;
    int decodeOk;
    StarCapture rebuilt;
    pipeline_u32 createdAtOut;
    pipeline_u8 pubkeyOut[PIPELINE_FMT_SIZE_PUBKEY];
    pipeline_u8 tagOut[PIPELINE_PACK_MAX_TAG_LEN];
    pipeline_u8 tagLenOut;
    pipeline_u8 nameOut[PIPELINE_PACK_MAX_NAME_LEN];
    pipeline_u8 nameLenOut;
    pipeline_u8 sigOut[PIPELINE_FMT_SIZE_SIG];
    int unpackRc;
    pipeline_u8 recomputedId[PIPELINE_EVENT_ID_SIZE];
    static const pipeline_u8 pubkey[PIPELINE_FMT_SIZE_PUBKEY] = PIPELINE_EVENT_PUBKEY_BYTES;
    static const pipeline_u8 gameTag[] = PIPELINE_EVENT_TAG_1_VALUE;
    int verifyOk;

    capture.course  = 15;
    capture.act     = 6;
    capture.coins   = 100;
    capture.frames  = 0x01020304u;
    capture.nonce16 = 0xCAFE;
    capture.keyId   = 0;

    buildOk = build_event(&capture, kBuildEventPrivkey, &event);
    check(buildOk != 0, "build_event succeeds end-to-end for a real StarCapture + key");
    if (!buildOk) {
        return;
    }

    /* Report the actual packed payload size: 113 B fixed (format v3's
     * FORMAT_TAG..PUBKEY..TAG_LEN..NAME_LEN..SIG spine, see
     * format_descriptor.json) plus this build's own per-game tag length
     * (4 for "sm64") plus this build's own baked event-name length (4 for
     * "TEST", spec #109 sub-issue #111 threads the real baked name into
     * build_event -- see build_event.c's own comment) = 121 B, comfortably
     * inside the v7/MEDIUM 122 B single-symbol ceiling
     * (PIPELINE_QR_MAX_PAYLOAD_BYTES). 138 B is format v3's own worst case
     * (TAG_LEN=10, NAME_LEN=15) and does NOT fit this ceiling -- see
     * qr_adapter.h's own comment on why that's expected, not a bug, under
     * ADR-0006's multi-frame transport. */
    check(PIPELINE_BUILT_PAYLOAD_SIZE == 121u,
          "build_event's packed_payload size is 121 B (113 + 4-byte \"sm64\" tag + 4-byte \"TEST\" name), "
          "within the v7/MEDIUM ceiling");

    /* (a) ADR-0006's transport envelope (spec #115, sub-issue #116): the
     * host decodes every emitted QR frame (ALPHANUMERIC-mode URLs, not raw
     * bytes), strips the known base URL, parses each fragment header, and
     * reassembles by index back to the exact packed_payload -- the
     * cabinet->jumper keystone round-trip, in natural frame order. See
     * test_build_event_multiframe_round_trip() below for the any-order and
     * missing-fragment coverage this same reassembler is put through. */
    check((int)event.frame_count == (int)PIPELINE_BUILT_FRAME_COUNT && event.frame_count >= 1u,
          "build_event reports a nonzero frame_count matching PIPELINE_BUILT_FRAME_COUNT");
    decodeOk = reassemble_built_event(&event, NULL, event.frame_count, decoded,
                                       (pipeline_u32)sizeof(decoded), &decodedLen);
    check(decodeOk != 0 && decodedLen == (pipeline_u32)PIPELINE_BUILT_PAYLOAD_SIZE &&
          memcmp(decoded, event.packed_payload, (size_t)PIPELINE_BUILT_PAYLOAD_SIZE) == 0,
          "build_event's N emitted QR frames decode+strip+debase32+reassemble back to the exact "
          "packed_payload byte-for-byte");

    /* (b) the host unpack adapter (format-descriptor-derived) rebuilds
     * EVERY field the companion needs straight off the wire -- capture,
     * createdAt, pubkey, and the per-game tag -- with no access to (or use
     * of) event_profile.h's baked macros below this point. */
    unpackRc = pipeline_unpack((const pipeline_u8 *)decoded, (pipeline_u32)decodedLen,
                                &rebuilt, &createdAtOut, pubkeyOut, tagOut, &tagLenOut,
                                nameOut, &nameLenOut, sigOut);
    check(unpackRc == PIPELINE_UNPACK_OK, "host pipeline_unpack accepts build_event's packed_payload");
    check(rebuilt.course == capture.course && rebuilt.act == capture.act &&
          rebuilt.coins == capture.coins && rebuilt.frames == capture.frames &&
          rebuilt.nonce16 == capture.nonce16 && rebuilt.keyId == capture.keyId,
          "unpacked StarCapture fields match the original capture exactly");
    check((pipeline_u32)createdAtOut == (pipeline_u32)PIPELINE_EVENT_CREATED_AT,
          "unpacked createdAt matches this build's baked created_at exactly (self-contained: it came off the wire)");
    check(memcmp(pubkeyOut, pubkey, PIPELINE_FMT_SIZE_PUBKEY) == 0,
          "unpacked pubkey matches this build's baked pubkey exactly (self-contained: it came off the wire)");
    check(tagLenOut == (pipeline_u8)PIPELINE_EVENT_TAG_1_LEN &&
          memcmp(tagOut, gameTag, tagLenOut) == 0,
          "unpacked per-game tag matches this build's baked tag exactly (self-contained: it came off the wire)");
    check(nameLenOut == (pipeline_u8)PIPELINE_EVENT_NAME_LEN &&
          memcmp(nameOut, PIPELINE_EVENT_NAME, nameLenOut) == 0,
          "unpacked event name matches this build's baked event name exactly (self-contained: it came off "
          "the wire -- spec #109, sub-issue #111)");

    /* (c) SELF-CONTAINED RECONSTRUCTION, with ZERO out-of-band constants:
     * recompute the id purely from the values pipeline_unpack() just
     * produced (createdAtOut/pubkeyOut/tagOut/rebuilt) via the GENERIC
     * event_id.h entry point -- never touching PIPELINE_EVENT_PUBKEY_HEX,
     * PIPELINE_EVENT_CREATED_AT, or PIPELINE_EVENT_TAG_1_VALUE directly for
     * this computation. This is the "companion reconstructs a broadcast-
     * ready event from the QR alone" acceptance criterion, proven at the
     * one pure seam (build_event()/pipeline_unpack()/event_id.h) this repo
     * exposes -- a real companion app (a different language, out of this
     * repo's scope) does the equivalent using docs/qr-handoff-spec.md. */
    pipeline_event_compute_id_from_fields(pubkeyOut, createdAtOut, (const char *)tagOut, tagLenOut,
                                           (const char *)nameOut, nameLenOut, &rebuilt, recomputedId);
    check(memcmp(recomputedId, kBuildEventExpectedIdA, PIPELINE_EVENT_ID_SIZE) == 0,
          "id recomputed from ONLY the unpacked wire fields matches the nostr-tools reference id (vector A)");

    check(memcmp(sigOut, kBuildEventExpectedSig, PIPELINE_SCHNORR_SIG_SIZE) == 0,
          "build_event's signature matches the independently-computed BIP-340 signature (@noble/curves oracle)");

    verifyOk = pipeline_schnorr_verify(recomputedId, pubkeyOut, sigOut);
    check(verifyOk != 0,
          "signature verifies against the wire-recomputed id and the wire-sourced pubkey "
          "(the companion's whole self-verify story, from the QR alone)");

    /* (d) a single flipped payload byte fails verification. Flip a content
     * byte (COURSE), not the signature itself: pipeline_unpack still
     * accepts the structurally well-formed payload and returns the
     * ORIGINAL (untouched) signature, but the rebuilt StarCapture's id no
     * longer matches what that signature actually signs, so verification
     * against it must fail -- proving the signature is tamper-evident over
     * the packed content, not just structurally checked.
     *
     * Scope note: this holds for COURSE/ACT/COINS/FRAMES/NONCE16/KEY_ID --
     * the exact fields event_id.c's pipeline_event_build_content() serializes
     * into the signed content (event_id.h's own documented content shape) --
     * and for the SIG bytes themselves (any change there is, trivially, a
     * different signature). KEY_ID (the star index) is signed content: a
     * flipped KEY_ID byte changes the recomputed id, so the signature check
     * fails, closing the earlier tamper hole for stars where `act` alone
     * doesn't identify which star was grabbed. It also holds for NAME
     * (format v3, spec #109 sub-issue #111): the event name is now signed
     * content too, folded into the ["n",...] tag, so a flipped NAME byte
     * changes the recomputed id exactly like COURSE/KEY_ID -- see the
     * dedicated NAME check below. It does NOT hold for FORMAT_TAG, which
     * pipeline_unpack() checks structurally (see the second check below),
     * not cryptographically. */
    {
        pipeline_u8 corrupted[PIPELINE_BUILT_PAYLOAD_SIZE];
        StarCapture corruptCapture;
        pipeline_u32 corruptCreatedAt;
        pipeline_u8 corruptPubkey[PIPELINE_FMT_SIZE_PUBKEY];
        pipeline_u8 corruptTag[PIPELINE_PACK_MAX_TAG_LEN];
        pipeline_u8 corruptTagLen;
        pipeline_u8 corruptName[PIPELINE_PACK_MAX_NAME_LEN];
        pipeline_u8 corruptNameLen;
        pipeline_u8 corruptSig[PIPELINE_FMT_SIZE_SIG];
        pipeline_u8 corruptId[PIPELINE_EVENT_ID_SIZE];
        int corruptVerify;
        int corruptUnpackRc;

        memcpy(corrupted, event.packed_payload, (size_t)PIPELINE_BUILT_PAYLOAD_SIZE);
        corrupted[PIPELINE_FMT_OFF_COURSE] ^= 0x01;

        pipeline_unpack(corrupted, (pipeline_u32)PIPELINE_BUILT_PAYLOAD_SIZE, &corruptCapture,
                         &corruptCreatedAt, corruptPubkey, corruptTag, &corruptTagLen,
                         corruptName, &corruptNameLen, corruptSig);
        pipeline_event_compute_id_from_fields(corruptPubkey, corruptCreatedAt, (const char *)corruptTag,
                                               corruptTagLen, (const char *)corruptName, corruptNameLen,
                                               &corruptCapture, corruptId);
        corruptVerify = pipeline_schnorr_verify(corruptId, corruptPubkey, corruptSig);
        check(corruptVerify == 0,
              "flipping one packed_payload byte (a signed content field) makes signature verification fail");

        /* A flipped FORMAT_TAG byte is rejected structurally, before
         * verification is even attempted -- a different, but equally
         * real, tamper-evidence path. */
        memcpy(corrupted, event.packed_payload, (size_t)PIPELINE_BUILT_PAYLOAD_SIZE);
        corrupted[PIPELINE_FMT_OFF_FORMAT_TAG] ^= 0x01;
        corruptUnpackRc = pipeline_unpack(corrupted, (pipeline_u32)PIPELINE_BUILT_PAYLOAD_SIZE, &corruptCapture,
                                           &corruptCreatedAt, corruptPubkey, corruptTag, &corruptTagLen,
                                           corruptName, &corruptNameLen, corruptSig);
        check(corruptUnpackRc == PIPELINE_UNPACK_ERR_BAD_FORMAT_TAG,
              "flipping the FORMAT_TAG byte is rejected structurally by pipeline_unpack");

        /* A flipped KEY_ID byte (the star index) must also fail verification:
         * keyId is signed content, so tampering with which star was grabbed
         * breaks the signature -- the regression guard for the tamper hole
         * closed by adding keyId to pipeline_event_build_content(). */
        memcpy(corrupted, event.packed_payload, (size_t)PIPELINE_BUILT_PAYLOAD_SIZE);
        corrupted[PIPELINE_FMT_OFF_KEY_ID] ^= 0x01;
        pipeline_unpack(corrupted, (pipeline_u32)PIPELINE_BUILT_PAYLOAD_SIZE, &corruptCapture,
                         &corruptCreatedAt, corruptPubkey, corruptTag, &corruptTagLen,
                         corruptName, &corruptNameLen, corruptSig);
        pipeline_event_compute_id_from_fields(corruptPubkey, corruptCreatedAt, (const char *)corruptTag,
                                               corruptTagLen, (const char *)corruptName, corruptNameLen,
                                               &corruptCapture, corruptId);
        corruptVerify = pipeline_schnorr_verify(corruptId, corruptPubkey, corruptSig);
        check(corruptVerify == 0,
              "flipping the KEY_ID byte (signed star index) makes signature verification fail");

        /* A flipped NAME byte must also fail verification -- the direct
         * regression guard for spec #109 sub-issue #111's own acceptance
         * criterion (the signed `id` commits to the event name): the name
         * is now signed content (folded into the ["n",...] tag by
         * event_id.c's pipeline_event_serialize()), so tampering with it
         * post-signing must break verification exactly like COURSE/KEY_ID
         * above, not just structurally round-trip through pipeline_unpack. */
        memcpy(corrupted, event.packed_payload, (size_t)PIPELINE_BUILT_PAYLOAD_SIZE);
        corrupted[PIPELINE_FMT_OFF_NAME((pipeline_u32)PIPELINE_EVENT_TAG_1_LEN)] ^= 0x01;
        pipeline_unpack(corrupted, (pipeline_u32)PIPELINE_BUILT_PAYLOAD_SIZE, &corruptCapture,
                         &corruptCreatedAt, corruptPubkey, corruptTag, &corruptTagLen,
                         corruptName, &corruptNameLen, corruptSig);
        pipeline_event_compute_id_from_fields(corruptPubkey, corruptCreatedAt, (const char *)corruptTag,
                                               corruptTagLen, (const char *)corruptName, corruptNameLen,
                                               &corruptCapture, corruptId);
        corruptVerify = pipeline_schnorr_verify(corruptId, corruptPubkey, corruptSig);
        check(corruptVerify == 0,
              "flipping a NAME byte (the signed event name) makes signature verification fail");
    }
}

/*
 * pipeline_unpack() boundary/rejection tests (spec #52, sub-issue #54's
 * original explicit acceptance criteria for TAG_LEN, extended by spec #109
 * sub-issue #110's own acceptance criteria for NAME_LEN and the v2->v3
 * FORMAT_TAG cutover): FORMAT_TAG != 0x03 rejected (in particular the old
 * v2 value 0x02, sub-issue #110's own explicit acceptance criterion);
 * TAG_LEN > 10 rejected; NAME_LEN > 15 rejected; wrong total length
 * rejected; TAG_LEN/NAME_LEN at their 0 and max legal boundaries accepted,
 * one past each max rejected. Exercises pipeline_pack()/pipeline_unpack()
 * directly (the internal seam both build_event() and a real companion
 * decoder are built on), not build_event() itself, since these are almost
 * all payloads build_event() itself could never produce (a real ROM
 * build's own tag/name lengths are fixed) -- proving pipeline_unpack() is a
 * genuinely defensive decoder for ARBITRARY (but wire-legal) incoming
 * payloads, not just self-consistent with this build's own pack side.
 */
static void test_pipeline_unpack_boundary_and_rejections(void)
{
    StarCapture capture;
    pipeline_u8 sig[PIPELINE_FMT_SIZE_SIG];
    pipeline_u8 pubkey[PIPELINE_FMT_SIZE_PUBKEY];
    pipeline_u8 packed[PIPELINE_PACK_MAX_SIZE];
    pipeline_u32 packedLen;
    StarCapture unpackedCapture;
    pipeline_u32 unpackedCreatedAt;
    pipeline_u8 unpackedPubkey[PIPELINE_FMT_SIZE_PUBKEY];
    pipeline_u8 unpackedTag[PIPELINE_PACK_MAX_TAG_LEN];
    pipeline_u8 unpackedTagLen;
    pipeline_u8 unpackedName[PIPELINE_PACK_MAX_NAME_LEN];
    pipeline_u8 unpackedNameLen;
    pipeline_u8 unpackedSig[PIPELINE_FMT_SIZE_SIG];
    int rc;
    int i;

    capture.course = 1; capture.act = 2; capture.coins = 3; capture.frames = 4u; capture.nonce16 = 5; capture.keyId = 6;
    for (i = 0; i < (int)PIPELINE_FMT_SIZE_SIG; i++) sig[i] = (pipeline_u8)(i + 1);
    for (i = 0; i < (int)PIPELINE_FMT_SIZE_PUBKEY; i++) pubkey[i] = (pipeline_u8)(i * 2 + 1);

    /* TAG_LEN == 0, NAME_LEN == 0 (minimum legal boundary for both):
     * accepted. */
    packedLen = pipeline_pack(&capture, 1700000000u, pubkey, (const pipeline_u8 *)"", 0,
                               (const pipeline_u8 *)"", 0, sig, packed);
    check(packedLen == PIPELINE_FMT_FIXED_SIZE, "pipeline_pack with TAG_LEN=NAME_LEN=0 writes exactly PIPELINE_FMT_FIXED_SIZE bytes");
    rc = pipeline_unpack(packed, packedLen, &unpackedCapture, &unpackedCreatedAt, unpackedPubkey,
                          unpackedTag, &unpackedTagLen, unpackedName, &unpackedNameLen, unpackedSig);
    check(rc == PIPELINE_UNPACK_OK && unpackedTagLen == 0 && unpackedNameLen == 0,
          "pipeline_unpack accepts the TAG_LEN=NAME_LEN=0 boundary payload");
    check(unpackedCapture.course == capture.course && unpackedCreatedAt == 1700000000u &&
          memcmp(unpackedPubkey, pubkey, PIPELINE_FMT_SIZE_PUBKEY) == 0 && memcmp(unpackedSig, sig, PIPELINE_FMT_SIZE_SIG) == 0,
          "TAG_LEN=NAME_LEN=0 payload round-trips every other field exactly");

    /* TAG_LEN == 10, NAME_LEN == 15 (maximum legal boundary for both): accepted. */
    packedLen = pipeline_pack(&capture, 1700000000u, pubkey, (const pipeline_u8 *)"0123456789", 10,
                               (const pipeline_u8 *)"FIFTEEN CHAR!!!", 15, sig, packed);
    check(packedLen == PIPELINE_FMT_FIXED_SIZE + 10u + 15u,
          "pipeline_pack with TAG_LEN=10, NAME_LEN=15 writes exactly PIPELINE_FMT_FIXED_SIZE+10+15 bytes");
    rc = pipeline_unpack(packed, packedLen, &unpackedCapture, &unpackedCreatedAt, unpackedPubkey,
                          unpackedTag, &unpackedTagLen, unpackedName, &unpackedNameLen, unpackedSig);
    check(rc == PIPELINE_UNPACK_OK && unpackedTagLen == 10 &&
          memcmp(unpackedTag, "0123456789", 10) == 0,
          "pipeline_unpack accepts the TAG_LEN=10 boundary payload and round-trips the tag bytes exactly");
    check(unpackedNameLen == 15 && memcmp(unpackedName, "FIFTEEN CHAR!!!", 15) == 0,
          "pipeline_unpack accepts the NAME_LEN=15 boundary payload and round-trips the name bytes exactly");

    /* TAG_LEN == 11: pipeline_pack() itself refuses (defensive, since no
     * real build ever asks for this); hand-craft the wire bytes directly to
     * prove pipeline_unpack() independently rejects an 11-byte tag. */
    check(pipeline_pack(&capture, 1700000000u, pubkey, (const pipeline_u8 *)"01234567890", 11,
                         (const pipeline_u8 *)"", 0, sig, packed) == 0,
          "pipeline_pack itself refuses tagLen=11 (over PIPELINE_PACK_MAX_TAG_LEN)");
    {
        pipeline_u8 handCrafted[PIPELINE_PACK_MAX_SIZE];
        pipeline_u32 handLen = PIPELINE_FMT_FIXED_SIZE + 11u;
        memset(handCrafted, 0, sizeof(handCrafted));
        handCrafted[PIPELINE_FMT_OFF_FORMAT_TAG] = (pipeline_u8)PIPELINE_FMT_TAG_VALUE;
        handCrafted[PIPELINE_FMT_OFF_TAG_LEN] = 11;
        rc = pipeline_unpack(handCrafted, handLen, &unpackedCapture, &unpackedCreatedAt, unpackedPubkey,
                              unpackedTag, &unpackedTagLen, unpackedName, &unpackedNameLen, unpackedSig);
        check(rc == PIPELINE_UNPACK_ERR_TAG_TOO_LONG,
              "pipeline_unpack rejects TAG_LEN=11 (one past the v7-MEDIUM boundary) even with a length-matched buffer");
    }

    /* NAME_LEN == 16: pipeline_pack() itself refuses (defensive, mirroring
     * TAG_LEN's own over-budget refusal); hand-craft the wire bytes
     * directly to prove pipeline_unpack() independently rejects a
     * 16-byte name (PIPELINE_PACK_MAX_NAME_LEN is 15). */
    check(pipeline_pack(&capture, 1700000000u, pubkey, (const pipeline_u8 *)"", 0,
                         (const pipeline_u8 *)"SIXTEEN CHARS!!!", 16, sig, packed) == 0,
          "pipeline_pack itself refuses nameLen=16 (over PIPELINE_PACK_MAX_NAME_LEN)");
    {
        pipeline_u8 handCrafted[PIPELINE_PACK_MAX_SIZE];
        pipeline_u32 handLen = PIPELINE_FMT_FIXED_SIZE + 16u;
        memset(handCrafted, 0, sizeof(handCrafted));
        handCrafted[PIPELINE_FMT_OFF_FORMAT_TAG] = (pipeline_u8)PIPELINE_FMT_TAG_VALUE;
        handCrafted[PIPELINE_FMT_OFF_TAG_LEN] = 0;
        handCrafted[PIPELINE_FMT_OFF_NAME_LEN(0)] = 16;
        rc = pipeline_unpack(handCrafted, handLen, &unpackedCapture, &unpackedCreatedAt, unpackedPubkey,
                              unpackedTag, &unpackedTagLen, unpackedName, &unpackedNameLen, unpackedSig);
        check(rc == PIPELINE_UNPACK_ERR_NAME_TOO_LONG,
              "pipeline_unpack rejects NAME_LEN=16 (one past the max) even with a length-matched buffer");
    }

    /* FORMAT_TAG != 0x03 is rejected -- in particular the old format v2
     * value (0x02), sub-issue #110's own explicit acceptance criterion:
     * "a 0x02 payload is rejected". */
    packedLen = pipeline_pack(&capture, 1700000000u, pubkey, (const pipeline_u8 *)"sm64", 4,
                               (const pipeline_u8 *)"ARCADE NIGHT", 12, sig, packed);
    packed[PIPELINE_FMT_OFF_FORMAT_TAG] = 0x02;
    rc = pipeline_unpack(packed, packedLen, &unpackedCapture, &unpackedCreatedAt, unpackedPubkey,
                          unpackedTag, &unpackedTagLen, unpackedName, &unpackedNameLen, unpackedSig);
    check(rc == PIPELINE_UNPACK_ERR_BAD_FORMAT_TAG,
          "pipeline_unpack rejects FORMAT_TAG 0x02 (the old format v2 tag) -- not silently misread as v3");
    packed[PIPELINE_FMT_OFF_FORMAT_TAG] = 0x01;
    rc = pipeline_unpack(packed, packedLen, &unpackedCapture, &unpackedCreatedAt, unpackedPubkey,
                          unpackedTag, &unpackedTagLen, unpackedName, &unpackedNameLen, unpackedSig);
    check(rc == PIPELINE_UNPACK_ERR_BAD_FORMAT_TAG,
          "pipeline_unpack rejects FORMAT_TAG 0x01 (the old format v1 tag)");

    /* Wrong total length: a v3-tagged, otherwise well-formed payload whose
     * actual byte count doesn't match PIPELINE_FMT_TOTAL_SIZE(TAG_LEN, NAME_LEN). */
    packedLen = pipeline_pack(&capture, 1700000000u, pubkey, (const pipeline_u8 *)"sm64", 4,
                               (const pipeline_u8 *)"ARCADE NIGHT", 12, sig, packed);
    rc = pipeline_unpack(packed, packedLen - 1, &unpackedCapture, &unpackedCreatedAt, unpackedPubkey,
                          unpackedTag, &unpackedTagLen, unpackedName, &unpackedNameLen, unpackedSig);
    check(rc == PIPELINE_UNPACK_ERR_WRONG_LENGTH,
          "pipeline_unpack rejects a payload one byte SHORTER than TAG_LEN/NAME_LEN implies");
    rc = pipeline_unpack(packed, packedLen + 1, &unpackedCapture, &unpackedCreatedAt, unpackedPubkey,
                          unpackedTag, &unpackedTagLen, unpackedName, &unpackedNameLen, unpackedSig);
    check(rc == PIPELINE_UNPACK_ERR_WRONG_LENGTH,
          "pipeline_unpack rejects a payload one byte LONGER than TAG_LEN/NAME_LEN implies");
    rc = pipeline_unpack(packed, PIPELINE_FMT_FIXED_SIZE - 1u, &unpackedCapture, &unpackedCreatedAt, unpackedPubkey,
                          unpackedTag, &unpackedTagLen, unpackedName, &unpackedNameLen, unpackedSig);
    check(rc == PIPELINE_UNPACK_ERR_WRONG_LENGTH,
          "pipeline_unpack rejects a payload shorter than the minimum legal v3 length (TAG_LEN=NAME_LEN=0 case)");
}

/*
 * pipeline_pack()/pipeline_unpack() event-name round-trip (spec #109,
 * sub-issue #110's own primary acceptance criterion): a StarCapture packed
 * with a baked event name unpacks back to the identical name, at the host
 * pack/unpack seam -- proving the ROM pack side and the host unpack side
 * genuinely agree on where NAME_LEN/NAME live, mirroring
 * test_format_descriptor_round_trip()'s existing TAG coverage.
 */
static void test_pipeline_pack_unpack_name_round_trip(void)
{
    StarCapture capture;
    StarCapture roundTripped;
    pipeline_u8 sig[PIPELINE_FMT_SIZE_SIG];
    pipeline_u8 sigRoundTripped[PIPELINE_FMT_SIZE_SIG];
    pipeline_u8 pubkey[PIPELINE_FMT_SIZE_PUBKEY];
    pipeline_u8 pubkeyRoundTripped[PIPELINE_FMT_SIZE_PUBKEY];
    static const pipeline_u8 kTag[] = "sm64";
    const pipeline_u8 kTagLen = 4;
    static const pipeline_u8 kName[] = "SUMMER JAM 2026";
    const pipeline_u8 kNameLen = 15;
    pipeline_u8 tagRoundTripped[PIPELINE_PACK_MAX_TAG_LEN];
    pipeline_u8 tagLenRoundTripped;
    pipeline_u8 nameRoundTripped[PIPELINE_PACK_MAX_NAME_LEN];
    pipeline_u8 nameLenRoundTripped;
    pipeline_u32 createdAt = 1700000000u;
    pipeline_u32 createdAtRoundTripped;
    pipeline_u8 packed[PIPELINE_PACK_MAX_SIZE];
    pipeline_u32 packedLen;
    int i;
    int rc;

    capture.course  = 9;
    capture.act     = 3;
    capture.coins   = 55;
    capture.frames  = 0x0BADF00Du;
    capture.nonce16 = 0xBEEF;
    capture.keyId   = 1;

    for (i = 0; i < (int)PIPELINE_FMT_SIZE_SIG; i++) {
        sig[i] = (pipeline_u8)(i * 7 + 3);
    }
    for (i = 0; i < (int)PIPELINE_FMT_SIZE_PUBKEY; i++) {
        pubkey[i] = (pipeline_u8)(i * 11 + 5);
    }

    memset(packed, 0xAA, sizeof(packed));
    packedLen = pipeline_pack(&capture, createdAt, pubkey, kTag, kTagLen, kName, kNameLen, sig, packed);

    check(packed[0] == (pipeline_u8)0x03u, "packed v3 payload's first byte is FORMAT_TAG 0x03");
    check(packed[0] == PIPELINE_FMT_TAG_VALUE, "packed payload leads with the format tag");
    check(packedLen == PIPELINE_FMT_FIXED_SIZE + kTagLen + kNameLen,
          "pipeline_pack's actual output length includes both the tag and the name bytes");

    rc = pipeline_unpack(packed, packedLen, &roundTripped, &createdAtRoundTripped, pubkeyRoundTripped,
                          tagRoundTripped, &tagLenRoundTripped, nameRoundTripped, &nameLenRoundTripped,
                          sigRoundTripped);
    check(rc == PIPELINE_UNPACK_OK, "unpack accepts a v3 payload carrying an event name");
    check(roundTripped.course == capture.course &&
          roundTripped.act == capture.act &&
          roundTripped.coins == capture.coins &&
          roundTripped.frames == capture.frames &&
          roundTripped.nonce16 == capture.nonce16 &&
          roundTripped.keyId == capture.keyId,
          "unpack round-trips all StarCapture fields exactly alongside the event name");
    check(createdAtRoundTripped == createdAt, "unpack round-trips createdAt exactly alongside the event name");
    check(memcmp(pubkeyRoundTripped, pubkey, PIPELINE_FMT_SIZE_PUBKEY) == 0,
          "unpack round-trips the pubkey bytes exactly alongside the event name");
    check(tagLenRoundTripped == kTagLen && memcmp(tagRoundTripped, kTag, kTagLen) == 0,
          "unpack round-trips the per-game tag bytes exactly alongside the event name");
    check(nameLenRoundTripped == kNameLen && memcmp(nameRoundTripped, kName, kNameLen) == 0,
          "unpack round-trips the event name bytes exactly");
    check(memcmp(sig, sigRoundTripped, PIPELINE_FMT_SIZE_SIG) == 0,
          "unpack round-trips the signature bytes exactly alongside the event name");

    /* A v2-tagged payload (the old FORMAT_TAG value 0x02) is rejected --
     * #110's own explicit acceptance criterion. */
    packed[0] = 0x02;
    rc = pipeline_unpack(packed, packedLen, &roundTripped, &createdAtRoundTripped, pubkeyRoundTripped,
                          tagRoundTripped, &tagLenRoundTripped, nameRoundTripped, &nameLenRoundTripped,
                          sigRoundTripped);
    check(rc == PIPELINE_UNPACK_ERR_BAD_FORMAT_TAG, "unpack rejects a 0x02 (format v2) payload");
}

#define QR_RENDER_TEST_FB_WIDTH  320
#define QR_RENDER_TEST_FB_HEIGHT 240

/*
 * A fake QrRenderFont for the host tests (issue #84 / ADR-0004): the real
 * dialog font lives in segmented ROM data the host can't reach, so the pure
 * qr_render core takes the font as a seam. Every advance is a fixed 6px
 * (space 5px), and every glyph is a solid 8x16 block (all ia4 nibbles 0xF),
 * so a rendered glyph is detectable as a run of white pixels and the
 * word-wrap math is driven by known widths. The space code returns a NULL
 * glyph (nothing to draw).
 */
static unsigned char gFakeCharWidths[256];
static unsigned char gFakeSolidGlyph[64];

static const unsigned char *fake_font_glyph(void *ctx, unsigned char code) {
    (void) ctx;
    if (code == QR_RENDER_DIALOG_CODE_SPACE) {
        return NULL;
    }
    return gFakeSolidGlyph;
}

static void init_fake_font(QrRenderFont *font) {
    int i;
    for (i = 0; i < 256; i++) {
        gFakeCharWidths[i] = 6;
    }
    gFakeCharWidths[QR_RENDER_DIALOG_CODE_SPACE] = 5;
    for (i = 0; i < 64; i++) {
        gFakeSolidGlyph[i] = 0xFF;
    }
    font->charWidths = gFakeCharWidths;
    font->glyph = fake_font_glyph;
    font->ctx = NULL;
}

/*
 * qr_render overlay round-trip test (issue #84; was sub-issue #32's centered
 * blit). Renders the full overlay's QR (now 2px/module, flush-left at the
 * layout's qrX/qrY) and proves it still decodes to build_event's exact
 * packed payload -- the render->reconstruct->decode shape from the file
 * header, re-anchored on the new left-positioned geometry. Uses a
 * StarCapture distinct from vector A just to exercise a different payload,
 * signed with the same BIP-340 KAT privkey.
 */
static void test_qr_render_blit_round_trips_through_decode(void)
{
    StarCapture capture;
    BuiltEvent event;
    int buildOk;
    static unsigned short fb[QR_RENDER_TEST_FB_WIDTH * QR_RENDER_TEST_FB_HEIGHT];
    int gridSize;
    int imageSize;
    int originX, originY;
    int row, col;
    int allQuietZoneWhite = 1;
    int allBlocksExact = 1;
    pipeline_u8 reconstructed[PIPELINE_QR_BUFFER_LEN];
    unsigned char decoded[PIPELINE_BUILT_URL_MAX_LEN];
    int decodedLen = -1;
    int decodeOk;
    int px, py;
    int i;

    capture.course  = 3;
    capture.act     = 1;
    capture.coins   = 42;
    capture.frames  = 0x0A0B0C0Du;
    capture.nonce16 = 0xBEEF;
    capture.keyId   = 0;

    buildOk = build_event(&capture, kBuildEventPrivkey, &event);
    check(buildOk != 0, "qr_render: build_event succeeds for the render test's StarCapture");
    if (!buildOk) {
        return;
    }

    /* Sentinel-fill the whole framebuffer with a color qr_render never
     * writes (neither QR_RENDER_WHITE_RGBA16 nor QR_RENDER_BLACK_RGBA16),
     * so the geometry assertions below can't accidentally pass against
     * leftover zero-initialized memory. */
    for (i = 0; i < QR_RENDER_TEST_FB_WIDTH * QR_RENDER_TEST_FB_HEIGHT; i++) {
        fb[i] = 0x1234;
    }

    /* Compute expected geometry and assert the image fits BEFORE calling
     * the blit -- qr_render_blit_qr_at() itself now refuses to write
     * anything if this doesn't hold (see qr_render.c's own defensive
     * bound), but this test's own geometry assertions must not run after
     * a call that could, in principle, already have misbehaved. */
    gridSize  = pipeline_qr_get_size(event.qr_bitmaps[0]);
    imageSize = (gridSize + 2 * QR_RENDER_QUIET_ZONE_MODULES) * QR_RENDER_MODULE_SCALE_PX;

    /* Left-positioned origin now comes from the pure layout (QR flush-left of
     * the horizontally-centered QR+box pair), not from centering the QR in
     * the whole framebuffer. */
    {
        QrRenderFont font;
        QrRenderLayout layout;
        init_fake_font(&font);
        qr_render_layout(gridSize, QR_RENDER_TEST_FB_WIDTH, QR_RENDER_TEST_FB_HEIGHT, &font,
                         QR_RENDER_COPY_HEADING, QR_RENDER_COPY_BODY, QR_RENDER_COPY_PROMPT,
                         &layout);
        check(layout.fits, "qr_render: overlay layout fits the 320x240 framebuffer");
        originX = layout.qrX;
        originY = layout.qrY;
    }

    check(imageSize == QR_RENDER_IMAGE_SIZE_PX,
          "qr_render: computed image size matches QR_RENDER_IMAGE_SIZE_PX (106x106 for v7/scale2/quiet4)");
    check(imageSize <= QR_RENDER_TEST_FB_WIDTH && imageSize <= QR_RENDER_TEST_FB_HEIGHT,
          "qr_render: image fits within the 320x240 N64 framebuffer");
    if (imageSize > QR_RENDER_TEST_FB_WIDTH || imageSize > QR_RENDER_TEST_FB_HEIGHT) {
        return;
    }

    qr_render_blit_qr_at(event.qr_bitmaps[0], fb, QR_RENDER_TEST_FB_WIDTH, QR_RENDER_TEST_FB_HEIGHT,
                         originX, originY);

    /* Quiet-zone assertion: every pixel in the fixed-width quiet-zone ring
     * is exactly QR_RENDER_WHITE_RGBA16 -- never the pre-blit sentinel and
     * never black. */
    for (py = 0; py < imageSize && allQuietZoneWhite; py++) {
        for (px = 0; px < imageSize; px++) {
            int moduleCol = px / QR_RENDER_MODULE_SCALE_PX - QR_RENDER_QUIET_ZONE_MODULES;
            int moduleRow = py / QR_RENDER_MODULE_SCALE_PX - QR_RENDER_QUIET_ZONE_MODULES;
            int inQuietZone = moduleCol < 0 || moduleCol >= gridSize || moduleRow < 0 || moduleRow >= gridSize;
            if (inQuietZone) {
                unsigned short pixel = fb[(originY + py) * QR_RENDER_TEST_FB_WIDTH + (originX + px)];
                if (pixel != QR_RENDER_WHITE_RGBA16) {
                    allQuietZoneWhite = 0;
                    break;
                }
            }
        }
    }
    check(allQuietZoneWhite, "qr_render: every quiet-zone pixel is exactly QR_RENDER_WHITE_RGBA16");

    /* Module-scale exactness: every pixel within a module's scaled block
     * matches that module's own color -- the scale is exact, not
     * approximate or off-by-one. */
    for (row = 0; row < gridSize && allBlocksExact; row++) {
        for (col = 0; col < gridSize && allBlocksExact; col++) {
            int isDark = pipeline_qr_get_module(event.qr_bitmaps[0], col, row);
            unsigned short expected = isDark ? QR_RENDER_BLACK_RGBA16 : QR_RENDER_WHITE_RGBA16;
            int blockX = originX + (QR_RENDER_QUIET_ZONE_MODULES + col) * QR_RENDER_MODULE_SCALE_PX;
            int blockY = originY + (QR_RENDER_QUIET_ZONE_MODULES + row) * QR_RENDER_MODULE_SCALE_PX;
            int dy, dx;
            for (dy = 0; dy < QR_RENDER_MODULE_SCALE_PX && allBlocksExact; dy++) {
                for (dx = 0; dx < QR_RENDER_MODULE_SCALE_PX; dx++) {
                    unsigned short pixel = fb[(blockY + dy) * QR_RENDER_TEST_FB_WIDTH + (blockX + dx)];
                    if (pixel != expected) {
                        allBlocksExact = 0;
                        break;
                    }
                }
            }
        }
    }
    check(allBlocksExact, "qr_render: every module's scaled block is an exact, uniform "
                           "QR_RENDER_MODULE_SCALE_PX-square color match");

    /* Reconstruct the module grid by sampling each module's CENTER pixel
     * back out of the RGBA16 buffer, and pack it into a qrcodegen-format
     * buffer (byte 0 = grid size; row-major bits, LSB-first per byte,
     * starting at byte 1 -- qrcodegen.c's own getModuleBounded()/
     * setModuleBounded() layout, the same format pipeline_qr_get_module()
     * reads), then feed it to the existing host QR decoder -- proving the
     * blit is faithful without a camera or emulator. */
    memset(reconstructed, 0, sizeof(reconstructed));
    reconstructed[0] = (pipeline_u8) gridSize;
    for (row = 0; row < gridSize; row++) {
        int blockY = originY + (QR_RENDER_QUIET_ZONE_MODULES + row) * QR_RENDER_MODULE_SCALE_PX;
        int sampleY = blockY + QR_RENDER_MODULE_SCALE_PX / 2;
        for (col = 0; col < gridSize; col++) {
            int blockX = originX + (QR_RENDER_QUIET_ZONE_MODULES + col) * QR_RENDER_MODULE_SCALE_PX;
            int sampleX = blockX + QR_RENDER_MODULE_SCALE_PX / 2;
            unsigned short pixel = fb[sampleY * QR_RENDER_TEST_FB_WIDTH + sampleX];
            int isDark = (pixel == QR_RENDER_BLACK_RGBA16);
            int index = row * gridSize + col;
            int bitIndex = index & 7;
            int byteIndex = (index >> 3) + 1;
            if (isDark) {
                reconstructed[byteIndex] |= (pipeline_u8) (1 << bitIndex);
            }
        }
    }

    decodeOk = qr_host_decode_alphanumeric(reconstructed, decoded, (int) sizeof(decoded), &decodedLen);

    /* Frame 0 now carries a URL-wrapped fragment (ADR-0006, spec #115
     * sub-issue #116), not raw payload bytes -- recompute the expected
     * text via the SAME production base32/fragment/url functions
     * build_event() itself calls, never a hand-duplicated literal. */
    {
        pipeline_u8 base32Text[PIPELINE_BUILT_BASE32_LEN];
        pipeline_u32 base32Len;
        pipeline_u8 fragment[PIPELINE_BUILT_FRAGMENT_BUDGET];
        pipeline_u32 fragmentLen;
        pipeline_u8 expectedUrl[PIPELINE_BUILT_URL_MAX_LEN];
        pipeline_u32 expectedUrlLen;
        static const pipeline_u8 kUrlBase[] = PIPELINE_URL_BASE;

        base32Len = pipeline_base32_encode(event.packed_payload, (pipeline_u32)PIPELINE_BUILT_PAYLOAD_SIZE,
                                            base32Text, (pipeline_u32)PIPELINE_BUILT_BASE32_LEN);
        pipeline_fragment_build(base32Text, base32Len, (pipeline_u32)PIPELINE_BUILT_FRAGMENT_BUDGET,
                                 0u, (pipeline_u32)PIPELINE_BUILT_FRAME_COUNT, fragment, &fragmentLen);
        expectedUrlLen = pipeline_url_wrap(kUrlBase, (pipeline_u32)PIPELINE_URL_BASE_LEN, fragment, fragmentLen,
                                            expectedUrl, (pipeline_u32)PIPELINE_BUILT_URL_MAX_LEN);

        check(decodeOk != 0 && (pipeline_u32)decodedLen == expectedUrlLen &&
              memcmp(decoded, expectedUrl, (size_t)expectedUrlLen) == 0,
              "qr_render: render->reconstruct->decode == build_event's exact frame-0 URL fragment");
    }
}

/*
 * qr_render_ascii_to_dialog(): the copy is authored ASCII but the font seam
 * is indexed by DIALOG char codes (charmap.txt). Pin the whole mapping the
 * overlay copy relies on, including the [A]-button sentinel and the
 * unknown -> space fallback (issue #84 / ADR-0004).
 */
static void test_qr_render_ascii_encoding(void) {
    int ok = 1;
    ok = ok && qr_render_ascii_to_dialog('0') == 0x00;
    ok = ok && qr_render_ascii_to_dialog('9') == 0x09;
    ok = ok && qr_render_ascii_to_dialog('A') == 0x0A;
    ok = ok && qr_render_ascii_to_dialog('Z') == 0x23;
    ok = ok && qr_render_ascii_to_dialog('a') == 0x24;
    ok = ok && qr_render_ascii_to_dialog('z') == 0x3D;
    ok = ok && qr_render_ascii_to_dialog(' ') == 0x9E;
    ok = ok && qr_render_ascii_to_dialog('!') == 0xF2;
    ok = ok && qr_render_ascii_to_dialog('.') == 0x3F;
    ok = ok && qr_render_ascii_to_dialog(',') == 0x6F;
    ok = ok && qr_render_ascii_to_dialog('\'') == 0x3E;
    ok = ok && qr_render_ascii_to_dialog('\x01') == QR_RENDER_DIALOG_CODE_A_BUTTON;
    ok = ok && qr_render_ascii_to_dialog('@') == QR_RENDER_DIALOG_CODE_SPACE; /* unknown */
    check(ok, "qr_render: ASCII->dialog-code map (letters/digits/space/!/./,/'/[A]/fallback)");
}

/*
 * qr_render_layout(): the pure geometry plan (issue #84 / ADR-0004). Asserts
 * the 2px QR flush-left of a horizontally-centered pair, the ROM box height
 * formula, vertical centering, and that everything -- QR, box, and every
 * emitted glyph -- lands inside the 8px overscan band and the box interior.
 */
static void test_qr_render_layout_geometry(void) {
    QrRenderFont font;
    QrRenderLayout layout;
    QrRenderLayout tiny;
    int i;
    int allGlyphsInsideBox = 1;

    init_fake_font(&font);
    qr_render_layout(PIPELINE_QR_MODULE_SIZE, 320, 240, &font,
                     QR_RENDER_COPY_HEADING, QR_RENDER_COPY_BODY, QR_RENDER_COPY_PROMPT,
                     &layout);

    check(layout.fits, "qr_render layout: fits at 320x240");
    check(layout.qrImagePx == QR_RENDER_IMAGE_SIZE_PX && layout.qrImagePx == 106,
          "qr_render layout: QR image is 106px (45 modules + 2*4 quiet, 2px/module)");
    /* pair = 106 + 6 + 143 = 255; centered -> startX = (320-255)/2 = 32 */
    check(layout.qrX == 32, "qr_render layout: QR flush-left at x=32 (pair centered)");
    check(layout.qrY == (240 - 106) / 2, "qr_render layout: QR vertically centered");
    check(layout.boxX == 32 + 106 + QR_RENDER_PAIR_GAP_PX,
          "qr_render layout: box sits one gap right of the QR");
    check(layout.boxW == QR_RENDER_DLG_BOX_W, "qr_render layout: box is the ROM 143px width");
    check(layout.boxH == QR_RENDER_DLG_LINE_PITCH * layout.lineCount + 8,
          "qr_render layout: box height is the ROM formula 16*lines + 8");
    check(layout.lineCount >= 3, "qr_render layout: >= 3 lines (heading + body + prompt)");
    check(layout.boxY == (240 - layout.boxH) / 2, "qr_render layout: box vertically centered");

    /* Overscan-safe band: everything within [8, 232). */
    check(layout.qrY >= QR_RENDER_OVERSCAN_PX
          && layout.qrY + layout.qrImagePx <= 240 - QR_RENDER_OVERSCAN_PX,
          "qr_render layout: QR within the 8px overscan band");
    check(layout.boxY >= QR_RENDER_OVERSCAN_PX
          && layout.boxY + layout.boxH <= 240 - QR_RENDER_OVERSCAN_PX,
          "qr_render layout: box within the 8px overscan band");

    check(layout.glyphCount > 0, "qr_render layout: emits glyph ops");
    for (i = 0; i < layout.glyphCount; i++) {
        QrRenderGlyphOp *op = &layout.glyphs[i];
        if (op->x < layout.boxX + QR_RENDER_DLG_BOX_INSET
            || op->x + QR_RENDER_GLYPH_W > layout.boxX + layout.boxW
            || op->y < layout.boxY
            || op->y + QR_RENDER_GLYPH_H > layout.boxY + layout.boxH) {
            allGlyphsInsideBox = 0;
            break;
        }
    }
    check(allGlyphsInsideBox, "qr_render layout: every glyph op lands inside the box interior");

    /* A framebuffer too small for the pair reports !fits and emits nothing. */
    qr_render_layout(PIPELINE_QR_MODULE_SIZE, 120, 120, &font,
                     QR_RENDER_COPY_HEADING, QR_RENDER_COPY_BODY, QR_RENDER_COPY_PROMPT,
                     &tiny);
    check(!tiny.fits && tiny.glyphCount == 0,
          "qr_render layout: !fits (and no glyphs) when the pair can't fit");
}

/*
 * qr_render_overlay_rgba16(): the composite paint. Proves the QR still
 * decodes from its left origin, the dialog box darkens the frozen frame
 * where no glyph covers it, and a real (fake-solid) glyph writes white
 * pixels over the darkened box (issue #84 / ADR-0004).
 */
static void test_qr_render_overlay_paint(void) {
    StarCapture capture;
    BuiltEvent event;
    QrRenderFont font;
    QrRenderLayout layout;
    static unsigned short fb[QR_RENDER_TEST_FB_WIDTH * QR_RENDER_TEST_FB_HEIGHT];
    unsigned short cornerBefore, cornerAfter, cornerExpected;
    int r, g, b;
    int i;
    int buildOk;

    capture.course = 5; capture.act = 2; capture.coins = 7;
    capture.frames = 0x11223344u; capture.nonce16 = 0xC0DE; capture.keyId = 0;
    buildOk = build_event(&capture, kBuildEventPrivkey, &event);
    check(buildOk != 0, "qr_render overlay: build_event succeeds for the paint test");
    if (!buildOk) {
        return;
    }

    init_fake_font(&font);
    qr_render_layout(pipeline_qr_get_size(event.qr_bitmaps[0]),
                     QR_RENDER_TEST_FB_WIDTH, QR_RENDER_TEST_FB_HEIGHT, &font,
                     QR_RENDER_COPY_HEADING, QR_RENDER_COPY_BODY, QR_RENDER_COPY_PROMPT,
                     &layout);
    check(layout.fits && layout.glyphCount > 0, "qr_render overlay: layout usable for paint");
    if (!layout.fits || layout.glyphCount == 0) {
        return;
    }

    for (i = 0; i < QR_RENDER_TEST_FB_WIDTH * QR_RENDER_TEST_FB_HEIGHT; i++) {
        fb[i] = 0x1234; /* sentinel the box blend must transform */
    }

    /* Box top-left corner is box-only: past the QR, above/left of any glyph
     * (glyphs start at inset 7 / top pad 4). Capture it before/after. */
    cornerBefore = fb[layout.boxY * QR_RENDER_TEST_FB_WIDTH + layout.boxX];

    qr_render_overlay_rgba16(event.qr_bitmaps[0], fb, QR_RENDER_TEST_FB_WIDTH,
                             QR_RENDER_TEST_FB_HEIGHT, &font);

    cornerAfter = fb[layout.boxY * QR_RENDER_TEST_FB_WIDTH + layout.boxX];
    r = ((0x1234 >> 11) & 0x1F) * QR_RENDER_DLG_BOX_KEEP / 255;
    g = ((0x1234 >> 6) & 0x1F) * QR_RENDER_DLG_BOX_KEEP / 255;
    b = ((0x1234 >> 1) & 0x1F) * QR_RENDER_DLG_BOX_KEEP / 255;
    cornerExpected = (unsigned short) ((r << 11) | (g << 6) | (b << 1) | 1);
    check(cornerBefore == 0x1234 && cornerAfter == cornerExpected,
          "qr_render overlay: box darkens the frozen frame toward black (alpha ~150)");

    /* The first glyph is a solid fake block; its top-left pixel is white. */
    check(fb[layout.glyphs[0].y * QR_RENDER_TEST_FB_WIDTH + layout.glyphs[0].x]
          == QR_RENDER_WHITE_RGBA16,
          "qr_render overlay: an authentic-path glyph writes white over the box");

    /* And the QR still decodes from its left origin -- to the exact frame-0
     * URL fragment build_event() emitted (ADR-0006's ALPHANUMERIC-mode
     * transport envelope, spec #115 sub-issue #116, not raw payload bytes
     * any more). The expected URL is recomputed via the SAME production
     * base32/fragment/url functions build_event() itself calls, never a
     * hand-duplicated literal. */
    {
        pipeline_u8 reconstructed[PIPELINE_QR_BUFFER_LEN];
        unsigned char decoded[PIPELINE_BUILT_URL_MAX_LEN];
        int decodedLen = -1;
        int gridSize = pipeline_qr_get_size(event.qr_bitmaps[0]);
        int row, col;
        int decodeOk;
        pipeline_u8 base32Text[PIPELINE_BUILT_BASE32_LEN];
        pipeline_u32 base32Len;
        pipeline_u8 fragment[PIPELINE_BUILT_FRAGMENT_BUDGET];
        pipeline_u32 fragmentLen;
        pipeline_u8 expectedUrl[PIPELINE_BUILT_URL_MAX_LEN];
        pipeline_u32 expectedUrlLen;
        static const pipeline_u8 kUrlBase[] = PIPELINE_URL_BASE;

        memset(reconstructed, 0, sizeof(reconstructed));
        reconstructed[0] = (pipeline_u8) gridSize;
        for (row = 0; row < gridSize; row++) {
            int sampleY = layout.qrY + (QR_RENDER_QUIET_ZONE_MODULES + row) * QR_RENDER_MODULE_SCALE_PX
                          + QR_RENDER_MODULE_SCALE_PX / 2;
            for (col = 0; col < gridSize; col++) {
                int sampleX = layout.qrX + (QR_RENDER_QUIET_ZONE_MODULES + col) * QR_RENDER_MODULE_SCALE_PX
                              + QR_RENDER_MODULE_SCALE_PX / 2;
                unsigned short pixel = fb[sampleY * QR_RENDER_TEST_FB_WIDTH + sampleX];
                int index = row * gridSize + col;
                if (pixel == QR_RENDER_BLACK_RGBA16) {
                    reconstructed[(index >> 3) + 1] |= (pipeline_u8) (1 << (index & 7));
                }
            }
        }
        decodeOk = qr_host_decode_alphanumeric(reconstructed, decoded, (int) sizeof(decoded), &decodedLen);

        base32Len = pipeline_base32_encode(event.packed_payload, (pipeline_u32)PIPELINE_BUILT_PAYLOAD_SIZE,
                                            base32Text, (pipeline_u32)PIPELINE_BUILT_BASE32_LEN);
        pipeline_fragment_build(base32Text, base32Len, (pipeline_u32)PIPELINE_BUILT_FRAGMENT_BUDGET,
                                 0u, (pipeline_u32)PIPELINE_BUILT_FRAME_COUNT, fragment, &fragmentLen);
        expectedUrlLen = pipeline_url_wrap(kUrlBase, (pipeline_u32)PIPELINE_URL_BASE_LEN, fragment, fragmentLen,
                                            expectedUrl, (pipeline_u32)PIPELINE_BUILT_URL_MAX_LEN);

        check(decodeOk != 0 && (pipeline_u32)decodedLen == expectedUrlLen
              && memcmp(decoded, expectedUrl, (size_t)expectedUrlLen) == 0,
              "qr_render overlay: QR still decodes to build_event's exact frame-0 URL fragment from its left origin");
    }
}

/*
 * Regression test for the garbled-dialog-text bug (star-capture QR screen):
 * the ROM's US dialog font glyph (main_font_lut[code]) is a 16-wide x 8-tall
 * ia4 texture that the in-game engine draws through gSPTextureRectangleFlip
 * (segment2.c dl_ia_text_tex_settings: SetTileSize S=16, T=8) -- i.e. the
 * stored texels are the 8x16 on-screen glyph TRANSPOSED-AND-FLIPPED. The
 * pure core decoded them as a plain 8-wide x 16-tall, 4-bytes/row image, so
 * every glyph came out scrambled (garbled white text). The existing
 * overlay test could never catch this: its fake glyph is a SOLID block,
 * invariant under exactly the transform that was wrong.
 *
 * This test feeds the REAL committed 'L' glyph bytes
 * (textures/segment2/font_graphics.05E40.ia4.inc.c -- the source PNG is a
 * 16x8 image of the letter L) through the font seam and asserts the ON-SCREEN
 * glyph has the left vertical stroke of an upright 'L' at the pixels the true
 * letter occupies. The expectation is anchored to ground truth (the asset IS
 * an L), not to the fix's own transform, so it stays honest.
 */
static const unsigned char kRealGlyphL[64] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x0f,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x0f,0x00,0x00,0x00,0x00,0xf0,0x00,
    0x00,0x0f,0x00,0x00,0x0f,0xff,0x00,0x00,
    0x00,0x00,0xff,0xff,0xf0,0x00,0x00,0x00,
};

static const unsigned char *real_L_font_glyph(void *ctx, unsigned char code) {
    (void) ctx;
    if (code == QR_RENDER_DIALOG_CODE_SPACE) {
        return NULL;
    }
    return kRealGlyphL;
}

static void test_qr_render_glyph_orientation(void) {
    StarCapture capture;
    BuiltEvent event;
    QrRenderFont font;
    QrRenderLayout layout;
    static unsigned short fb[QR_RENDER_TEST_FB_WIDTH * QR_RENDER_TEST_FB_HEIGHT];
    int ox, oy, gy;
    int leftStrokeOn = 1;
    int buildOk;
    int i;

    capture.course = 1; capture.act = 1; capture.coins = 0;
    capture.frames = 1u; capture.nonce16 = 0x1234; capture.keyId = 0;
    buildOk = build_event(&capture, kBuildEventPrivkey, &event);
    check(buildOk != 0, "qr_render glyph orientation: build_event succeeds");
    if (!buildOk) {
        return;
    }

    /* Fixed 8px advances so cells are exactly the 8px glyph width apart:
     * the first cell's leftmost column (gx == 0) can't be written by any
     * neighbor. */
    for (i = 0; i < 256; i++) {
        gFakeCharWidths[i] = 8;
    }
    font.charWidths = gFakeCharWidths;
    font.glyph = real_L_font_glyph;
    font.ctx = NULL;

    qr_render_layout(pipeline_qr_get_size(event.qr_bitmaps[0]),
                     QR_RENDER_TEST_FB_WIDTH, QR_RENDER_TEST_FB_HEIGHT, &font,
                     QR_RENDER_COPY_HEADING, QR_RENDER_COPY_BODY, QR_RENDER_COPY_PROMPT,
                     &layout);
    check(layout.fits && layout.glyphCount > 0, "qr_render glyph orientation: layout usable");
    if (!layout.fits || layout.glyphCount == 0) {
        return;
    }

    for (i = 0; i < QR_RENDER_TEST_FB_WIDTH * QR_RENDER_TEST_FB_HEIGHT; i++) {
        fb[i] = QR_RENDER_BLACK_RGBA16;
    }
    qr_render_overlay_rgba16(event.qr_bitmaps[0], fb, QR_RENDER_TEST_FB_WIDTH,
                             QR_RENDER_TEST_FB_HEIGHT, &font);

    /* Upright 'L' from the real bytes has a solid left vertical stroke:
     * on-screen column gx == 0 is "on" for rows gy == 7..11 (verified against
     * the asset). The buggy transpose leaves gx == 0 blank on those rows and
     * scatters the pixels elsewhere. */
    ox = layout.glyphs[0].x;
    oy = layout.glyphs[0].y;
    for (gy = 7; gy <= 11; gy++) {
        if (fb[(oy + gy) * QR_RENDER_TEST_FB_WIDTH + ox] != QR_RENDER_WHITE_RGBA16) {
            leftStrokeOn = 0;
        }
    }
    check(leftStrokeOn,
          "qr_render glyph orientation: real 'L' renders its left vertical stroke "
          "(font ia4 is 16x8 flipped, not a plain 8x16 image)");
}

/*
 * BIP-340 test vector 0: secret key 3, x-only pubkey
 * F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9.
 * The Makefile generates event_profile.h from this exact private key (see
 * TEST_PRIVKEY_HEX), so PIPELINE_EVENT_PUBKEY_HEX/_BYTES here must match.
 */
static const pipeline_u8 kExpectedPubkey[32] = {
    0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10,
    0x49, 0x34, 0x4f, 0x85, 0xf8, 0x9d, 0x52, 0x29,
    0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f, 0x99, 0xb0,
    0x86, 0x01, 0xf1, 0x13, 0xbc, 0xe0, 0x36, 0xf9,
};
static const char kExpectedPubkeyHex[] =
    "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

static void test_pubkey_known_answer(void)
{
    static const pipeline_u8 pubkeyBytes[32] = PIPELINE_EVENT_PUBKEY_BYTES;

    check(memcmp(pubkeyBytes, kExpectedPubkey, 32) == 0,
          "derived x-only pubkey matches BIP-340 KAT (privkey=3) [byte array]");
    check(strcmp(PIPELINE_EVENT_PUBKEY_HEX, kExpectedPubkeyHex) == 0,
          "derived x-only pubkey matches BIP-340 KAT (privkey=3) [hex string]");
    check(PIPELINE_EVENT_KIND == 8064, "event profile kind is 8064");
}

static void test_format_descriptor_round_trip(void)
{
    StarCapture capture;
    StarCapture roundTripped;
    pipeline_u8 sig[PIPELINE_FMT_SIZE_SIG];
    pipeline_u8 sigRoundTripped[PIPELINE_FMT_SIZE_SIG];
    pipeline_u8 pubkey[PIPELINE_FMT_SIZE_PUBKEY];
    pipeline_u8 pubkeyRoundTripped[PIPELINE_FMT_SIZE_PUBKEY];
    static const pipeline_u8 kTag[] = "sm64";
    const pipeline_u8 kTagLen = 4;
    pipeline_u8 tagRoundTripped[PIPELINE_PACK_MAX_TAG_LEN];
    pipeline_u8 tagLenRoundTripped;
    /* No event name in THIS test (a zero-length NAME) -- see
     * test_pipeline_pack_unpack_name_round_trip() for the dedicated NAME
     * coverage (spec #109, sub-issue #110). */
    pipeline_u8 nameRoundTripped[PIPELINE_PACK_MAX_NAME_LEN];
    pipeline_u8 nameLenRoundTripped;
    pipeline_u32 createdAt = 1700000000u;
    pipeline_u32 createdAtRoundTripped;
    pipeline_u8 packed[PIPELINE_PACK_MAX_SIZE];
    pipeline_u32 packedLen;
    int i;
    int rc;

    capture.course  = 15;
    capture.act     = 6;
    capture.coins   = 100;
    capture.frames  = 0x01020304u;
    capture.nonce16 = 0xCAFE;
    capture.keyId   = 7;

    for (i = 0; i < (int)PIPELINE_FMT_SIZE_SIG; i++) {
        sig[i] = (pipeline_u8)(i * 3 + 1);
    }
    for (i = 0; i < (int)PIPELINE_FMT_SIZE_PUBKEY; i++) {
        pubkey[i] = (pipeline_u8)(i * 5 + 2);
    }

    memset(packed, 0xFF, sizeof(packed));
    packedLen = pipeline_pack(&capture, createdAt, pubkey, kTag, kTagLen,
                               (const pipeline_u8 *)"", 0, sig, packed);

    check(packed[0] == PIPELINE_FMT_TAG_VALUE, "packed payload leads with the format tag");
    /* Literal 113, not PIPELINE_FMT_FIXED_SIZE: this pins the descriptor's
     * own fixed-size accounting to an independently-computed value (1 + 1 +
     * 1 + 1 + 4 + 2 + 1 + 4 + 32 + 1 + 1 + 64, format v3's spine plus the
     * new NAME_LEN byte), rather than comparing the macro to itself. Total
     * for THIS 4-byte tag and zero-length name is 113 + 4 = 117. */
    check(PIPELINE_FMT_FIXED_SIZE == 113u,
          "format descriptor's fixed size matches the expected field layout (format v3)");
    check(packedLen == 117u, "pipeline_pack's actual output length is 113 + this test's 4-byte tag");

    rc = pipeline_unpack(packed, packedLen, &roundTripped, &createdAtRoundTripped, pubkeyRoundTripped,
                          tagRoundTripped, &tagLenRoundTripped, nameRoundTripped, &nameLenRoundTripped,
                          sigRoundTripped);
    check(rc == PIPELINE_UNPACK_OK, "unpack accepts a correctly-tagged payload");
    check(roundTripped.course == capture.course &&
          roundTripped.act == capture.act &&
          roundTripped.coins == capture.coins &&
          roundTripped.frames == capture.frames &&
          roundTripped.nonce16 == capture.nonce16 &&
          roundTripped.keyId == capture.keyId,
          "unpack round-trips all StarCapture fields exactly");
    check(createdAtRoundTripped == createdAt, "unpack round-trips createdAt exactly");
    check(memcmp(pubkeyRoundTripped, pubkey, PIPELINE_FMT_SIZE_PUBKEY) == 0, "unpack round-trips the pubkey bytes exactly");
    check(tagLenRoundTripped == kTagLen && memcmp(tagRoundTripped, kTag, kTagLen) == 0,
          "unpack round-trips the per-game tag bytes exactly");
    check(nameLenRoundTripped == 0, "unpack round-trips the (zero-length) event name exactly");
    check(memcmp(sig, sigRoundTripped, PIPELINE_FMT_SIZE_SIG) == 0,
          "unpack round-trips the signature bytes exactly");

    /* Corrupt the format tag and confirm unpack rejects it. */
    packed[0] = (pipeline_u8)(PIPELINE_FMT_TAG_VALUE + 1);
    rc = pipeline_unpack(packed, packedLen, &roundTripped, &createdAtRoundTripped, pubkeyRoundTripped,
                          tagRoundTripped, &tagLenRoundTripped, nameRoundTripped, &nameLenRoundTripped,
                          sigRoundTripped);
    check(rc == PIPELINE_UNPACK_ERR_BAD_FORMAT_TAG, "unpack rejects a payload with the wrong format tag");
}

/*
 * QR round-trip tests (spec #24, sub-issue #27). Exercises the internal
 * seam directly: pipeline_qr_encode() (qr_adapter.h, which hides the
 * ported qrcodegen.c behind it) followed by qr_host_decode() (host-only,
 * tools/pipeline_test/qr_host_decode.c -- never linked into the ROM). See
 * qr_adapter.h for the version 7 / ECC MEDIUM / fixed-mask /
 * 122-byte-usable-payload (124 total data codewords, minus the mode+count
 * header) choice (spec #52, sub-issue #53).
 */
static void fill_pattern(pipeline_u8 *buf, int len, pipeline_u8 seed)
{
    int i;
    for (i = 0; i < len; i++) {
        buf[i] = (pipeline_u8)(seed + i * 7 + (i * i) % 251);
    }
}

static void check_round_trip(int len, const char *label)
{
    pipeline_u8 payload[PIPELINE_QR_MAX_PAYLOAD_BYTES];
    pipeline_u8 qrcode[PIPELINE_QR_BUFFER_LEN];
    unsigned char decoded[PIPELINE_QR_MAX_PAYLOAD_BYTES];
    int decodedLen = -1;
    int encodeOk, decodeOk;
    char what[128];

    fill_pattern(payload, len, (pipeline_u8)(len * 3 + 1));

    encodeOk = pipeline_qr_encode(payload, (pipeline_u32)len, qrcode);
    snprintf(what, sizeof(what), "QR encode succeeds for %s (%d bytes, within budget)", label, len);
    check(encodeOk != 0, what);
    if (!encodeOk) {
        return;
    }

    decodeOk = qr_host_decode(qrcode, decoded, (int)sizeof(decoded), &decodedLen);
    snprintf(what, sizeof(what), "QR decode succeeds for %s (%d bytes)", label, len);
    check(decodeOk != 0, what);

    snprintf(what, sizeof(what), "QR round-trip is byte-exact for %s (%d bytes)", label, len);
    check(decodeOk && decodedLen == len && memcmp(decoded, payload, (size_t)len) == 0, what);
}

static void test_qr_round_trip_representative_sizes(void)
{
    check_round_trip(1, "minimal payload");
    check_round_trip(4, "sub-issue #25 stub payload size");
    check_round_trip(24, "spec #24's ~24 B variable content estimate");
    check_round_trip(75, "the old format v1 total size (pre-#54 history)");
    check_round_trip(PIPELINE_BUILT_PAYLOAD_SIZE, "this build's format v3 packed payload size (113 + TAG_LEN + NAME_LEN)");
    check_round_trip(88, "spec #24's ~88 B payload budget");
    check_round_trip(PIPELINE_QR_MAX_PAYLOAD_BYTES, "exact version 7 / ECC MEDIUM usable payload capacity (122 B)");
}

static void test_qr_rejects_over_budget_cleanly(void)
{
    pipeline_u8 payload[PIPELINE_QR_MAX_PAYLOAD_BYTES + 1];
    pipeline_u8 qrcode[PIPELINE_QR_BUFFER_LEN];
    int encodeOk;

    fill_pattern(payload, (int)sizeof(payload), 0x5A);

    /* One byte over the real version 7 / ECC MEDIUM capacity: must be
     * rejected cleanly (nonzero return, no truncated/partial QR Code
     * written -- qrcode[0] is left at the documented invalid-size
     * sentinel of 0), never silently truncated to fit. */
    memset(qrcode, 0xFF, sizeof(qrcode));
    encodeOk = pipeline_qr_encode(payload, (pipeline_u32)sizeof(payload), qrcode);
    check(encodeOk == 0, "QR encode rejects a payload one byte over the 122 B usable payload capacity");
    check(qrcode[0] == 0, "rejected QR encode leaves the invalid-size sentinel, not a truncated code");

    /* Far over budget too (well past even the raw bitmap buffer size) --
     * must still be a clean rejection, not a buffer overrun. */
    {
        pipeline_u8 hugePayload[PIPELINE_QR_BUFFER_LEN * 4];
        memset(hugePayload, 0x42, sizeof(hugePayload));
        memset(qrcode, 0xFF, sizeof(qrcode));
        encodeOk = pipeline_qr_encode(hugePayload, (pipeline_u32)sizeof(hugePayload), qrcode);
        check(encodeOk == 0, "QR encode rejects a grossly over-budget payload cleanly");
        check(qrcode[0] == 0, "grossly-over-budget rejection also leaves the invalid-size sentinel");
    }
}

/*
 * ADR-0006's airgap transport envelope (spec #115, sub-issue #116): base32
 * codec, fragmenter, URL wrapper, ALPHANUMERIC QR round-trip, and the
 * full build_event() multi-frame keystone round-trip.
 */

/*
 * pipeline_qr_encode_alphanumeric()/qr_host_decode_alphanumeric() round
 * trip -- the QR encoder's other segment mode, added for ADR-0006's
 * URL-wrapped fragment frames. Mirrors test_qr_round_trip_representative_
 * sizes()'s BYTE-mode shape above but at the ALPHANUMERIC charset/budget.
 */
static void fill_alnum_pattern(pipeline_u8 *buf, int len)
{
    /* A test-only fixture pattern (not a wire constant): cycles through
     * the QR alphanumeric charset so encode/decode exercise every symbol,
     * not just digits. */
    static const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
    int i;
    for (i = 0; i < len; i++) {
        buf[i] = (pipeline_u8)charset[i % 45];
    }
}

static void test_qr_alphanumeric_round_trip_and_rejections(void)
{
    pipeline_u8 text[PIPELINE_QR_ALNUM_MAX_CHARS];
    pipeline_u8 qrcode[PIPELINE_QR_BUFFER_LEN];
    unsigned char decoded[PIPELINE_QR_ALNUM_MAX_CHARS];
    int decodedLen = -1;
    int encodeOk, decodeOk;

    /* A realistic URL-shaped string (odd character count) round-trips
     * exactly. */
    {
        static const char url[] = "HTTPS://SM64NOSTR.PAGES.DEV/0102ABCDEFGHIJKLMNOP";
        int len = (int)(sizeof(url) - 1);
        encodeOk = pipeline_qr_encode_alphanumeric((const pipeline_u8 *)url, (pipeline_u32)len, qrcode);
        check(encodeOk != 0, "QR alphanumeric encode succeeds for a URL-shaped alphanumeric string");
        decodeOk = qr_host_decode_alphanumeric(qrcode, decoded, (int)sizeof(decoded), &decodedLen);
        check(decodeOk != 0 && decodedLen == len && memcmp(decoded, url, (size_t)len) == 0,
              "QR alphanumeric round-trip is byte-exact for a URL-shaped string (odd character count)");
    }

    /* Exact max budget (178 chars, an even count) round-trips. */
    {
        fill_alnum_pattern(text, PIPELINE_QR_ALNUM_MAX_CHARS);
        encodeOk = pipeline_qr_encode_alphanumeric(text, (pipeline_u32)PIPELINE_QR_ALNUM_MAX_CHARS, qrcode);
        check(encodeOk != 0, "QR alphanumeric encode succeeds at exactly PIPELINE_QR_ALNUM_MAX_CHARS (178)");
        decodeOk = qr_host_decode_alphanumeric(qrcode, decoded, (int)sizeof(decoded), &decodedLen);
        check(decodeOk != 0 && decodedLen == PIPELINE_QR_ALNUM_MAX_CHARS &&
              memcmp(decoded, text, (size_t)PIPELINE_QR_ALNUM_MAX_CHARS) == 0,
              "QR alphanumeric round-trip is byte-exact at the max budget");
    }

    /* One character over budget: cleanly rejected, no truncation. */
    {
        pipeline_u8 overBudget[PIPELINE_QR_ALNUM_MAX_CHARS + 1];
        fill_alnum_pattern(overBudget, (int)sizeof(overBudget));
        memset(qrcode, 0xFF, sizeof(qrcode));
        encodeOk = pipeline_qr_encode_alphanumeric(overBudget, (pipeline_u32)sizeof(overBudget), qrcode);
        check(encodeOk == 0, "QR alphanumeric encode rejects one character over budget (179)");
        check(qrcode[0] == 0, "rejected alphanumeric encode leaves the invalid-size sentinel");
    }

    /* An odd character count (a trailing 6-bit single character) round-trips too. */
    {
        fill_alnum_pattern(text, 5);
        encodeOk = pipeline_qr_encode_alphanumeric(text, 5u, qrcode);
        check(encodeOk != 0, "QR alphanumeric encode succeeds for an odd (5) character count");
        decodeOk = qr_host_decode_alphanumeric(qrcode, decoded, (int)sizeof(decoded), &decodedLen);
        check(decodeOk != 0 && decodedLen == 5 && memcmp(decoded, text, 5) == 0,
              "QR alphanumeric round-trip is byte-exact for an odd character count (trailing 6-bit char)");
    }

    /* A byte outside the alphanumeric charset (lowercase, never legal on
     * this build's all-uppercase wire) is rejected, not silently coerced. */
    {
        pipeline_u8 badText[8];
        memcpy(badText, "HTTPS://", 8);
        badText[0] = (pipeline_u8)'h'; /* lowercase */
        memset(qrcode, 0xFF, sizeof(qrcode));
        encodeOk = pipeline_qr_encode_alphanumeric(badText, 8u, qrcode);
        check(encodeOk == 0, "QR alphanumeric encode rejects a non-alphanumeric-charset byte (lowercase)");
        check(qrcode[0] == 0, "rejected alphanumeric encode (bad charset) leaves the invalid-size sentinel");
    }
}

/*
 * base32 codec known-answer tests (spec #115, sub-issue #116): RFC 4648
 * section 10's own example vectors, adapted to this codec's no-padding
 * convention (upstream's vectors include trailing '=' padding; this codec
 * never emits or expects it -- base32.h's own header comment explains why
 * -- so each expected string below is upstream's vector with any trailing
 * '=' stripped).
 */
static void check_base32(const char *input, int inputLen, const char *expected, const char *what)
{
    pipeline_u8 encoded[64];
    pipeline_u32 encodedLen;
    int expectedLen = (int)strlen(expected);
    pipeline_u8 decoded[64];
    pipeline_u32 decodedLen = 0;
    int decodeOk;
    char whatDecode[192];

    encodedLen = pipeline_base32_encode((const pipeline_u8 *)input, (pipeline_u32)inputLen,
                                         encoded, (pipeline_u32)sizeof(encoded));
    check(encodedLen == (pipeline_u32)expectedLen && memcmp(encoded, expected, (size_t)expectedLen) == 0, what);

    decodeOk = pipeline_base32_decode(encoded, encodedLen, decoded, (pipeline_u32)sizeof(decoded), &decodedLen);
    snprintf(whatDecode, sizeof(whatDecode), "%s (decode is the exact inverse)", what);
    check(decodeOk != 0 && decodedLen == (pipeline_u32)inputLen &&
          memcmp(decoded, input, (size_t)inputLen) == 0, whatDecode);
}

static void test_base32_known_answer_vectors(void)
{
    check_base32("", 0, "", "base32(\"\") == \"\" (RFC 4648 section 10)");
    check_base32("f", 1, "MY", "base32(\"f\") == \"MY\" (RFC 4648 section 10, no padding)");
    check_base32("fo", 2, "MZXQ", "base32(\"fo\") == \"MZXQ\" (RFC 4648 section 10, no padding)");
    check_base32("foo", 3, "MZXW6", "base32(\"foo\") == \"MZXW6\" (RFC 4648 section 10, no padding)");
    check_base32("foob", 4, "MZXW6YQ", "base32(\"foob\") == \"MZXW6YQ\" (RFC 4648 section 10, no padding)");
    check_base32("fooba", 5, "MZXW6YTB", "base32(\"fooba\") == \"MZXW6YTB\" (RFC 4648 section 10, no padding)");
    check_base32("foobar", 6, "MZXW6YTBOI", "base32(\"foobar\") == \"MZXW6YTBOI\" (RFC 4648 section 10, no padding)");

    /* Decode-side rejection: a non-alphabet byte (including a literal '='
     * -- this codec's wire never carries padding) is rejected, not
     * silently skipped. */
    {
        pipeline_u8 decoded[16];
        pipeline_u32 decodedLen = 0;
        int decodeOk = pipeline_base32_decode((const pipeline_u8 *)"MY======", 8, decoded, (pipeline_u32)sizeof(decoded), &decodedLen);
        check(decodeOk == 0, "pipeline_base32_decode rejects a literal '=' padding byte");
    }
    {
        pipeline_u8 decoded[16];
        pipeline_u32 decodedLen = 0;
        int decodeOk = pipeline_base32_decode((const pipeline_u8 *)"my", 2, decoded, (pipeline_u32)sizeof(decoded), &decodedLen);
        check(decodeOk == 0, "pipeline_base32_decode rejects lowercase (this codec is uppercase-only)");
    }
}

/*
 * Fragmenter boundary + header round-trip tests (spec #115, sub-issue
 * #116): pipeline_fragment_count()/pipeline_fragment_build()/
 * pipeline_fragment_parse_header() are pure functions of (base32 length,
 * per-frame alnum budget) -- exercised directly here, hand-computed,
 * independent of any real build_event() payload (see
 * test_build_event_multiframe_round_trip()'s own header comment for why
 * the genuine N=1 boundary is pinned HERE rather than at the build_event
 * seam).
 */
static void test_fragment_boundaries_and_header_round_trip(void)
{
    pipeline_u8 base32Text[16];
    pipeline_u32 count;
    pipeline_u8 fragment[16];
    pipeline_u32 fragmentLen = 0;
    pipeline_u32 idx, cnt;
    int i;

    for (i = 0; i < 16; i++) {
        base32Text[i] = (pipeline_u8)('A' + (i % 26));
    }

    /* N=1 boundary: a payload that exactly fills one frame's chunk budget
     * (perFrameBudget=10 -> 4-byte header + 6-byte chunk cap) still
     * reports N=1, not N=2. */
    count = pipeline_fragment_count(6u, 10u);
    check(count == 1u, "pipeline_fragment_count: base32Len == chunkCap reports N=1 (fits exactly)");

    /* Just-over-one-frame boundary: one character more than the chunk
     * budget forces a second frame. */
    count = pipeline_fragment_count(7u, 10u);
    check(count == 2u, "pipeline_fragment_count: base32Len == chunkCap+1 reports N=2 (just over one frame)");

    /* The degenerate empty-payload case is still N=1. */
    count = pipeline_fragment_count(0u, 10u);
    check(count == 1u, "pipeline_fragment_count: an empty payload still reports N=1 (degenerate case)");

    /* An invalid budget (no room for even one chunk byte after the fixed
     * header) is reported as invalid (0), not silently miscounted. */
    count = pipeline_fragment_count(6u, 4u);
    check(count == 0u, "pipeline_fragment_count: a budget with no room for a chunk byte is invalid (0)");

    /* Build+parse round-trip at the N=2 boundary: fragment 0 gets exactly
     * chunkCap (6) chars, fragment 1 gets the 1 leftover char; both
     * headers parse back to their own index/count. */
    check(pipeline_fragment_build(base32Text, 7u, 10u, 0u, 2u, fragment, &fragmentLen) != 0 &&
          fragmentLen == 10u && memcmp(fragment + 4, base32Text, 6) == 0,
          "pipeline_fragment_build: fragment 0 of 2 carries the first 6-char chunk after its 4-char header");
    check(pipeline_fragment_parse_header(fragment, fragmentLen, &idx, &cnt) != 0 && idx == 0u && cnt == 2u,
          "pipeline_fragment_parse_header: fragment 0's header round-trips to index 0 of 2");

    check(pipeline_fragment_build(base32Text, 7u, 10u, 1u, 2u, fragment, &fragmentLen) != 0 &&
          fragmentLen == 5u && fragment[4] == base32Text[6],
          "pipeline_fragment_build: fragment 1 of 2 carries the trailing 1-char chunk after its 4-char header");
    check(pipeline_fragment_parse_header(fragment, fragmentLen, &idx, &cnt) != 0 && idx == 1u && cnt == 2u,
          "pipeline_fragment_parse_header: fragment 1's header round-trips to index 1 of 2");

    /* A structurally invalid header (index >= count) is rejected. */
    {
        pipeline_u8 badHeader[6];
        memcpy(badHeader, "ZZ01AB", 6); /* index "ZZ" (1295) >= count "01" (1) */
        check(pipeline_fragment_parse_header(badHeader, 6u, &idx, &cnt) == 0,
              "pipeline_fragment_parse_header rejects a header whose index >= its own count");
    }

    /* Rejects a bad request: frameIndex >= frameCount. */
    check(pipeline_fragment_build(base32Text, 7u, 10u, 2u, 2u, fragment, &fragmentLen) == 0,
          "pipeline_fragment_build rejects frameIndex >= frameCount");
}

/*
 * URL wrap/strip tests (spec #115, sub-issue #116): pipeline_url_wrap()/
 * pipeline_url_strip() are pure functions producing/consuming exactly
 * HTTPS://<base>/<fragment>, all-uppercase, path-based.
 */
static void test_url_wrap_and_strip(void)
{
    static const pipeline_u8 baseUrl[] = "EXAMPLE.TEST";
    pipeline_u32 baseUrlLen = (pipeline_u32)(sizeof(baseUrl) - 1);
    static const pipeline_u8 fragment[] = "0102ABCDEF";
    pipeline_u32 fragmentLen = (pipeline_u32)(sizeof(fragment) - 1);
    pipeline_u8 url[128];
    pipeline_u32 urlLen;
    pipeline_u8 stripped[64];
    pipeline_u32 strippedLen = 0;

    urlLen = pipeline_url_wrap(baseUrl, baseUrlLen, fragment, fragmentLen, url, (pipeline_u32)sizeof(url));
    check(urlLen == (pipeline_u32)(8 + 12 + 1 + 10) &&
          memcmp(url, "HTTPS://EXAMPLE.TEST/0102ABCDEF", (size_t)urlLen) == 0,
          "pipeline_url_wrap produces the exact expected all-uppercase path-based URL");

    check(pipeline_url_strip(url, urlLen, baseUrl, baseUrlLen, stripped, (pipeline_u32)sizeof(stripped),
                              &strippedLen) != 0 &&
          strippedLen == fragmentLen && memcmp(stripped, fragment, fragmentLen) == 0,
          "pipeline_url_strip recovers the exact original fragment");

    /* A URL wrapped around a DIFFERENT base is rejected, not silently
     * mis-stripped. */
    {
        static const pipeline_u8 wrongBase[] = "OTHER.TEST";
        check(pipeline_url_strip(url, urlLen, wrongBase, (pipeline_u32)(sizeof(wrongBase) - 1),
                                  stripped, (pipeline_u32)sizeof(stripped), &strippedLen) == 0,
              "pipeline_url_strip rejects a URL whose base doesn't match the expected one");
    }
    {
        pipeline_u8 truncated[4];
        memcpy(truncated, url, 4);
        check(pipeline_url_strip(truncated, 4u, baseUrl, baseUrlLen, stripped, (pipeline_u32)sizeof(stripped),
                                  &strippedLen) == 0,
              "pipeline_url_strip rejects a URL shorter than the expected prefix");
    }
}

/*
 * The ADR-0006 keystone round-trip, at the real build_event() seam (spec
 * #115, sub-issue #116): a real StarCapture + this host tool's own baked
 * default "sm64" tag + "TEST" name produces N>=2 frames under this
 * build's own baked PIPELINE_URL_BASE -- ADR-0006 itself observes the
 * honest v3 floor already overflows one frame once URL-wrapped under any
 * realistic domain (see docs/adr/0006's own "the honest floor overflows
 * one frame" argument), so this build's own N is expected to be >1, not a
 * hand-picked worst case (see tools/pipeline_test/Makefile's own comment
 * on TEST_URL_BASE). The genuine N=1 boundary is instead pinned directly
 * at the fragmenter (test_fragment_boundaries_and_header_round_trip()
 * above), since build_event()'s own frame count is a single compile-time
 * constant for this whole binary (PIPELINE_BUILT_FRAME_COUNT) and can't be
 * varied per call the way a real reader must handle across different
 * builds.
 */
static void test_build_event_multiframe_round_trip(void)
{
    StarCapture capture;
    BuiltEvent event;
    int buildOk;
    pipeline_u8 recovered[PIPELINE_BUILT_PAYLOAD_SIZE];
    pipeline_u32 recoveredLen = 0;
    int ok;
    StarCapture rebuilt;
    pipeline_u32 createdAtOut;
    pipeline_u8 pubkeyOut[PIPELINE_FMT_SIZE_PUBKEY];
    pipeline_u8 tagOut[PIPELINE_PACK_MAX_TAG_LEN];
    pipeline_u8 tagLenOut;
    pipeline_u8 nameOut[PIPELINE_PACK_MAX_NAME_LEN];
    pipeline_u8 nameLenOut;
    pipeline_u8 sigOut[PIPELINE_FMT_SIZE_SIG];
    int unpackRc;
    int reversedOrder[PIPELINE_BUILT_FRAME_COUNT];
    pipeline_u32 i;

    capture.course  = 8;
    capture.act     = 4;
    capture.coins   = 50;
    capture.frames  = 0x0BAD0BADu;
    capture.nonce16 = 0xABCD;
    capture.keyId   = 1;

    buildOk = build_event(&capture, kBuildEventPrivkey, &event);
    check(buildOk != 0, "multiframe round-trip: build_event succeeds");
    if (!buildOk) {
        return;
    }

    check(event.frame_count >= 2u,
          "multiframe round-trip: this build's default \"sm64\" tag + representative event name "
          "produces N>=2 frames (spec #115 sub-issue #116's own acceptance criterion)");

    /* Natural order. */
    ok = reassemble_built_event(&event, NULL, event.frame_count, recovered,
                                 (pipeline_u32)sizeof(recovered), &recoveredLen);
    check(ok != 0 && recoveredLen == (pipeline_u32)PIPELINE_BUILT_PAYLOAD_SIZE &&
          memcmp(recovered, event.packed_payload, (size_t)PIPELINE_BUILT_PAYLOAD_SIZE) == 0,
          "multiframe round-trip: natural-order reassembly recovers the exact packed_payload");

    /* Any order: reversed. Fragments carry their own index, so arrival
     * order must never matter. */
    for (i = 0; i < event.frame_count; i++) {
        reversedOrder[i] = (int)(event.frame_count - 1u - i);
    }
    recoveredLen = 0;
    ok = reassemble_built_event(&event, reversedOrder, event.frame_count, recovered,
                                 (pipeline_u32)sizeof(recovered), &recoveredLen);
    check(ok != 0 && recoveredLen == (pipeline_u32)PIPELINE_BUILT_PAYLOAD_SIZE &&
          memcmp(recovered, event.packed_payload, (size_t)PIPELINE_BUILT_PAYLOAD_SIZE) == 0,
          "multiframe round-trip: reverse-order reassembly still recovers the exact packed_payload");

    /* Missing fragment: drop the last frame -- reports incomplete, never a
     * wrong/partial event. */
    recoveredLen = 0;
    ok = reassemble_built_event(&event, NULL, event.frame_count - 1u, recovered,
                                 (pipeline_u32)sizeof(recovered), &recoveredLen);
    check(ok == 0, "multiframe round-trip: a missing fragment reports incomplete, never a wrong/partial event");

    /* Recovered bytes unpack back to the original StarCapture, closing the
     * loop back to the unchanged v3 pack/unpack contract. */
    recoveredLen = 0;
    ok = reassemble_built_event(&event, NULL, event.frame_count, recovered,
                                 (pipeline_u32)sizeof(recovered), &recoveredLen);
    unpackRc = pipeline_unpack(recovered, recoveredLen, &rebuilt, &createdAtOut, pubkeyOut,
                                tagOut, &tagLenOut, nameOut, &nameLenOut, sigOut);
    check(ok != 0 && unpackRc == PIPELINE_UNPACK_OK,
          "multiframe round-trip: the reassembled bytes pipeline_unpack cleanly");
    check(rebuilt.course == capture.course && rebuilt.act == capture.act &&
          rebuilt.coins == capture.coins && rebuilt.frames == capture.frames &&
          rebuilt.nonce16 == capture.nonce16 && rebuilt.keyId == capture.keyId,
          "multiframe round-trip: the reassembled+unpacked StarCapture matches the original exactly");
}

/*
 * SHA-256 known-answer tests (spec #24, sub-issue #28). Vectors are the
 * standard published ones: FIPS 180-4's own examples (the empty string,
 * "abc", and the 56-byte two-block message), plus a 55/56-byte pair that
 * independently pins the single-vs-two-block padding branch in
 * sha256.c's pipeline_sha256_final() (55 bytes leaves room for the 0x80 +
 * length in the current block; 56 does not and must transform an extra
 * padding block first). All five double-checked against Node's own
 * crypto.createHash('sha256') as an independent oracle, not just quoted
 * from memory.
 */
static void check_sha256(const char *msg, int msgLen, const pipeline_u8 expected[PIPELINE_SHA256_DIGEST_SIZE], const char *what)
{
    pipeline_u8 hash[PIPELINE_SHA256_DIGEST_SIZE];

    pipeline_sha256((const pipeline_u8 *)msg, (pipeline_u32)msgLen, hash);
    check(memcmp(hash, expected, PIPELINE_SHA256_DIGEST_SIZE) == 0, what);
}

static void test_sha256_known_answer_vectors(void)
{
    static const pipeline_u8 kEmpty[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    static const pipeline_u8 kAbc[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    static const pipeline_u8 kTwoBlock[32] = {
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
    };
    static const pipeline_u8 k55a[32] = {
        0x9f, 0x43, 0x90, 0xf8, 0xd3, 0x0c, 0x2d, 0xd9, 0x2e, 0xc9, 0xf0, 0x95, 0xb6, 0x5e, 0x2b, 0x9a,
        0xe9, 0xb0, 0xa9, 0x25, 0xa5, 0x25, 0x8e, 0x24, 0x1c, 0x9f, 0x1e, 0x91, 0x0f, 0x73, 0x43, 0x18,
    };
    static const pipeline_u8 k56a[32] = {
        0xb3, 0x54, 0x39, 0xa4, 0xac, 0x6f, 0x09, 0x48, 0xb6, 0xd6, 0xf9, 0xe3, 0xc6, 0xaf, 0x0f, 0x5f,
        0x59, 0x0c, 0xe2, 0x0f, 0x1b, 0xde, 0x70, 0x90, 0xef, 0x79, 0x70, 0x68, 0x6e, 0xc6, 0x73, 0x8a,
    };
    char a55[55];
    char a56[56];
    pipeline_sha256_ctx ctx;
    pipeline_u8 streamed[PIPELINE_SHA256_DIGEST_SIZE];

    memset(a55, 'a', sizeof(a55));
    memset(a56, 'a', sizeof(a56));

    check_sha256("", 0, kEmpty, "SHA-256 KAT: empty string");
    check_sha256("abc", 3, kAbc, "SHA-256 KAT: \"abc\"");
    check_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, kTwoBlock,
                 "SHA-256 KAT: FIPS 180-4 two-block message");
    check_sha256(a55, (int)sizeof(a55), k55a, "SHA-256 KAT: 55 x 'a' (single-block padding branch)");
    check_sha256(a56, (int)sizeof(a56), k56a, "SHA-256 KAT: 56 x 'a' (two-block padding branch)");

    /* Same "abc" vector via the streaming init/update/final API, split
     * across multiple update() calls, to prove the incremental path (not
     * just the one-shot convenience wrapper) is also correct. */
    pipeline_sha256_init(&ctx);
    pipeline_sha256_update(&ctx, (const pipeline_u8 *)"a", 1);
    pipeline_sha256_update(&ctx, (const pipeline_u8 *)"b", 1);
    pipeline_sha256_update(&ctx, (const pipeline_u8 *)"c", 1);
    pipeline_sha256_final(&ctx, streamed);
    check(memcmp(streamed, kAbc, PIPELINE_SHA256_DIGEST_SIZE) == 0,
          "SHA-256 KAT: \"abc\" via streaming init/update/final API");
}

/*
 * Event id-equals-reference tests (spec #24, sub-issue #28).
 *
 * Reference oracle: the real `nostr-tools` npm package's getEventHash(),
 * run via tools/reference_event_id.js against the exact same
 * pubkey/created_at/kind/tags baked into this host tool's generated
 * event_profile.h (TEST_PRIVKEY_HEX = BIP-340 KAT privkey 3,
 * TEST_CREATED_AT = 1700000000 -- see the Makefile and
 * test_pubkey_known_answer() above) and the exact same StarCapture values
 * as below. nostr-tools is an independent oracle -- a real, separately
 * maintained upstream JS library used by real Nostr clients/relays, not a
 * second implementation of this same algorithm written for this test --
 * so this checks the pipeline's own serialize+SHA-256 id computation
 * (event_id.c) against ground truth, not against itself.
 */
static void check_event_id(const StarCapture *capture, const pipeline_u8 expectedId[PIPELINE_EVENT_ID_SIZE], const char *what)
{
    pipeline_u8 id[PIPELINE_EVENT_ID_SIZE];

    pipeline_event_compute_id(capture, id);
    check(memcmp(id, expectedId, PIPELINE_EVENT_ID_SIZE) == 0, what);
}

static void test_event_id_matches_reference(void)
{
    StarCapture captureA;
    StarCapture captureB;
    StarCapture captureC;

    /* Reference ids computed by tools/reference_event_id.js's "vector A/B/C"
     * against the real nostr-tools package -- see that script for the
     * exact command/output and the header comment above for why it's a
     * faithful independent oracle. Format v2 (spec #52, sub-issue #54):
     * these changed from their pre-v2 values because TAG_0 changed from
     * "cabinet-leaderboard" to the spec-pinned "ag-lb". Format v3 (spec
     * #109, sub-issue #111): these changed AGAIN because pipeline_event_
     * compute_id() (the baked-profile wrapper these vectors exercise) now
     * folds PIPELINE_EVENT_NAME into a third signed tag, ["n","TEST"] --
     * "TEST" is this host tool's own baked event name (Makefile's
     * --event-name, shortened from "HOST TEST" -- see its own comment). */
    static const pipeline_u8 kExpectedIdA[32] = {
        0x91, 0xff, 0x8d, 0xf5, 0x9c, 0x33, 0x9b, 0xf5, 0xc6, 0x43, 0x75, 0x0c, 0xdb, 0x1c, 0x7e, 0xdf,
        0x99, 0xc4, 0x8a, 0xa9, 0xce, 0x78, 0x79, 0xa2, 0x2c, 0x9a, 0x52, 0xda, 0x7b, 0x84, 0x36, 0x2f,
    };
    static const pipeline_u8 kExpectedIdB[32] = {
        0xe8, 0x03, 0x85, 0xaf, 0x51, 0x8c, 0xb2, 0xa2, 0x99, 0xc9, 0x7b, 0x94, 0x73, 0xa0, 0x8b, 0x44,
        0xc6, 0x74, 0x19, 0xab, 0x37, 0x19, 0x12, 0x65, 0x81, 0x0f, 0x9d, 0x68, 0x2d, 0xbe, 0x4c, 0x86,
    };
    static const pipeline_u8 kExpectedIdC[32] = {
        0x33, 0xe6, 0x40, 0xf7, 0xc6, 0xf0, 0x20, 0x09, 0x0d, 0xaf, 0xe0, 0x5f, 0x21, 0x02, 0x34, 0x59,
        0xdc, 0x9d, 0xbd, 0xc9, 0xf2, 0xf1, 0xd1, 0xff, 0x72, 0xed, 0x5b, 0x31, 0x7d, 0x67, 0xa8, 0x93,
    };

    captureA.course = 15; captureA.act = 6; captureA.coins = 100; captureA.frames = 0x01020304u; captureA.nonce16 = 0xCAFE; captureA.keyId = 0;
    captureB.course = 9;  captureB.act = 1; captureB.coins = 42;  captureB.frames = 1234u;        captureB.nonce16 = 0xBEEF; captureB.keyId = 0;
    captureC.course = 0;  captureC.act = 0; captureC.coins = 0;   captureC.frames = 0u;            captureC.nonce16 = 0;      captureC.keyId = 0;

    check_event_id(&captureA, kExpectedIdA, "event id matches nostr-tools reference (vector A)");
    check_event_id(&captureB, kExpectedIdB, "event id matches nostr-tools reference (vector B)");
    check_event_id(&captureC, kExpectedIdC, "event id matches nostr-tools reference (all-zero vector C)");
}

/*
 * Event name is signed content: changing ONLY the name changes `id` (spec
 * #109, sub-issue #111's own acceptance criterion, stated directly rather
 * than only proven transitively through the re-pinned oracle vectors above).
 * Uses pipeline_event_serialize_from_fields()/pipeline_event_compute_id_
 * from_fields() (the generic, non-baked-profile forms) so pubkey/createdAt/
 * tag1/capture can be held IDENTICAL across two calls while only name
 * varies -- isolating the one field under test the way check_event_id()
 * above (which always uses this build's single baked PIPELINE_EVENT_NAME)
 * cannot.
 */
static void test_event_name_change_changes_id(void)
{
    static const pipeline_u8 pubkey[PIPELINE_FMT_SIZE_PUBKEY] = PIPELINE_EVENT_PUBKEY_BYTES;
    static const char tag1[] = "sm64";
    static const char nameA[] = "ALPHA";
    static const char nameB[] = "BETA";
    StarCapture capture;
    pipeline_u8 idA[PIPELINE_EVENT_ID_SIZE];
    pipeline_u8 idB[PIPELINE_EVENT_ID_SIZE];
    pipeline_u8 idARepeat[PIPELINE_EVENT_ID_SIZE];

    capture.course = 15; capture.act = 6; capture.coins = 100; capture.frames = 0x01020304u;
    capture.nonce16 = 0xCAFE; capture.keyId = 0;

    pipeline_event_compute_id_from_fields(pubkey, 1700000000u, tag1, (pipeline_u32)(sizeof(tag1) - 1),
                                           nameA, (pipeline_u32)(sizeof(nameA) - 1), &capture, idA);
    pipeline_event_compute_id_from_fields(pubkey, 1700000000u, tag1, (pipeline_u32)(sizeof(tag1) - 1),
                                           nameB, (pipeline_u32)(sizeof(nameB) - 1), &capture, idB);
    pipeline_event_compute_id_from_fields(pubkey, 1700000000u, tag1, (pipeline_u32)(sizeof(tag1) - 1),
                                           nameA, (pipeline_u32)(sizeof(nameA) - 1), &capture, idARepeat);

    check(memcmp(idA, idB, PIPELINE_EVENT_ID_SIZE) != 0,
          "changing ONLY the event name (pubkey/createdAt/tag/capture held fixed) changes the signed id");
    check(memcmp(idA, idARepeat, PIPELINE_EVENT_ID_SIZE) == 0,
          "recomputing the id with the SAME name (and everything else fixed) reproduces the same id "
          "(sanity check on the differential comparison above)");
}

/*
 * Content double-serialization escaping test (spec #24, sub-issue #28).
 *
 * content is itself a JSON object serialized to a string
 * (pipeline_event_build_content), and that string is then embedded as a
 * *string element* of the outer event array (pipeline_event_serialize) --
 * so its `"` characters must come out as the two-byte escape `\"` in the
 * final serialized bytes. This asserts that directly against the raw
 * serialized buffer (not just indirectly via id equality above), so a
 * serializer bug that happened to cancel out in the hash could never hide
 * here.
 */
static void test_content_escaping_path(void)
{
    StarCapture capture;
    char content[PIPELINE_EVENT_CONTENT_MAX];
    pipeline_u8 serialized[PIPELINE_EVENT_SERIALIZED_MAX];
    pipeline_u32 contentLen;
    pipeline_u32 serializedLen;
    const char *expectedContent = "{\"course\":15,\"act\":6,\"coins\":100,\"frames\":16909060,\"nonce\":51966,\"keyId\":0}";
    /* The FULL expected canonical serialization for this exact StarCapture
     * (vector A, same as test_event_id_matches_reference()'s captureA) and
     * the baked event profile (pubkey f9308a.../created_at 1700000000/kind
     * 8064/the two t tags) -- cross-checked byte-for-byte against
     * JSON.stringify([0,pubkey,created_at,kind,tags,content]) via Node, the
     * same expression nostr-tools' getEventHash() evaluates (see
     * tools/reference_event_id.js). Pinning the whole buffer, not just a
     * substring, proves the prefix/field ordering/escaping directly rather
     * than only through the opaque id in the test above. Format v2 (spec
     * #52, sub-issue #54): TAG_0 changed from "cabinet-leaderboard" to the
     * spec-pinned "ag-lb" (205 B, was 219 B pre-v2). Format v3 (spec #109,
     * sub-issue #111): a third tag, ["n","TEST"], is now appended after the
     * two "t" tags -- "TEST" is this host tool's own baked event name (218 B,
     * was 205 B pre-#111). */
    const char *expectedSerialized =
        "[0,\"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9\","
        "1700000000,8064,[[\"t\",\"ag-lb\"],[\"t\",\"sm64\"],[\"n\",\"TEST\"]],"
        "\"{\\\"course\\\":15,\\\"act\\\":6,\\\"coins\\\":100,\\\"frames\\\":16909060,\\\"nonce\\\":51966,\\\"keyId\\\":0}\"]";

    capture.course = 15; capture.act = 6; capture.coins = 100; capture.frames = 0x01020304u; capture.nonce16 = 0xCAFE; capture.keyId = 0;

    contentLen = pipeline_event_build_content(&capture, content);
    check(contentLen == (pipeline_u32)strlen(expectedContent) && strcmp(content, expectedContent) == 0,
          "content JSON (unescaped, standalone) matches expected shape/values");

    serializedLen = pipeline_event_serialize(&capture, serialized);
    check(serializedLen < PIPELINE_EVENT_SERIALIZED_MAX, "serialized event fits within the fixed buffer bound");

    /* strcmp/strstr require NUL-terminated strings; serialized isn't
     * NUL-terminated by contract, so copy it into a NUL-terminated buffer
     * first (bounded by the same fixed max, plus one byte for the NUL). */
    {
        char serializedStr[PIPELINE_EVENT_SERIALIZED_MAX + 1];
        memcpy(serializedStr, serialized, serializedLen);
        serializedStr[serializedLen] = '\0';

        check(serializedLen == (pipeline_u32)strlen(expectedSerialized) &&
              strcmp(serializedStr, expectedSerialized) == 0,
              "serialized event matches the full expected canonical byte sequence, escaping included");
        check(strstr(serializedStr, "\"course\":") == NULL,
              "serialized event does NOT contain the unescaped raw content JSON verbatim");
    }
}

/*
 * BIP-340 Schnorr signing tests (spec #24, sub-issue #29).
 *
 * The KAT below is the published BIP-340 test vector 0
 * (bitcoin/bips/bip-0340/test-vectors.csv, row 0): secret key 3, aux_rand
 * all-zero, message all-zero, expected signature as given. secret key 3 is
 * the SAME BIP-340 KAT key already used for test_pubkey_known_answer()
 * above and baked into this host tool's generated event_profile.h
 * (TEST_PRIVKEY_HEX, see the Makefile) -- so kExpectedPubkeyHex there and
 * kPubkey here must (and do) agree.
 *
 * Independent verification: this signature was independently checked
 * against @noble/curves (a real, separately-maintained secp256k1/Schnorr
 * JS library -- see tools/verify_schnorr_reference.js for the accept/
 * tampered-reject run and why it's a genuine independent oracle, not a
 * second implementation of this same code). test_schnorr_verify_* below
 * uses this file's OWN pipeline_schnorr_verify() -- an internal
 * self-consistency check only, explicitly NOT that independent oracle
 * (see schnorr_adapter.h's own header comment on the distinction).
 */
static const pipeline_u8 kSchnorrPrivkey[PIPELINE_SCHNORR_PRIVKEY_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
};
static const pipeline_u8 kSchnorrMessageZero[PIPELINE_SCHNORR_MSG_SIZE] = {0};
static const pipeline_u8 kSchnorrExpectedSig[PIPELINE_SCHNORR_SIG_SIZE] = {
    0xe9, 0x07, 0x83, 0x1f, 0x80, 0x84, 0x8d, 0x10, 0x69, 0xa5, 0x37, 0x1b, 0x40, 0x24, 0x10, 0x36,
    0x4b, 0xdf, 0x1c, 0x5f, 0x83, 0x07, 0xb0, 0x08, 0x4c, 0x55, 0xf1, 0xce, 0x2d, 0xca, 0x82, 0x15,
    0x25, 0xf6, 0x6a, 0x4a, 0x85, 0xea, 0x8b, 0x71, 0xe4, 0x82, 0xa7, 0x4f, 0x38, 0x2d, 0x2c, 0xe5,
    0xeb, 0xee, 0xe8, 0xfd, 0xb2, 0x17, 0x2f, 0x47, 0x7d, 0xf4, 0x90, 0x0d, 0x31, 0x05, 0x36, 0xc0,
};

static void test_schnorr_signing_known_answer(void)
{
    pipeline_u8 sig[PIPELINE_SCHNORR_SIG_SIZE];
    int ok = pipeline_schnorr_sign(kSchnorrMessageZero, kSchnorrPrivkey, sig);

    check(ok != 0, "pipeline_schnorr_sign succeeds for the BIP-340 KAT (privkey=3, aux_rand=0, msg=0)");
    check(ok && memcmp(sig, kSchnorrExpectedSig, PIPELINE_SCHNORR_SIG_SIZE) == 0,
          "pipeline_schnorr_sign matches the published BIP-340 test vector 0 signature exactly");
}

static void test_schnorr_verify_internal_self_consistency(void)
{
    /* PIPELINE_EVENT_PUBKEY_BYTES is generated from TEST_PRIVKEY_HEX
     * (privkey 3, same as kSchnorrPrivkey above) -- see the Makefile and
     * test_pubkey_known_answer(). */
    static const pipeline_u8 pubkey[32] = PIPELINE_EVENT_PUBKEY_BYTES;
    int verifyOk = pipeline_schnorr_verify(kSchnorrMessageZero, pubkey, kSchnorrExpectedSig);
    pipeline_u8 tamperedMsg[PIPELINE_SCHNORR_MSG_SIZE];
    int tamperedOk;

    check(verifyOk != 0, "pipeline_schnorr_verify (internal) accepts the real KAT signature against the build's pubkey");

    memcpy(tamperedMsg, kSchnorrMessageZero, PIPELINE_SCHNORR_MSG_SIZE);
    tamperedMsg[0] ^= 1;
    tamperedOk = pipeline_schnorr_verify(tamperedMsg, pubkey, kSchnorrExpectedSig);
    check(tamperedOk == 0, "pipeline_schnorr_verify (internal) rejects the same signature against a tampered id");
}

static void test_schnorr_sign_is_deterministic(void)
{
    /* Full-pipeline determinism (spec #24's signing decision): signing the
     * same (privkey, message) twice must yield byte-identical output --
     * aux_rand is always the fixed all-zero value, never sourced from
     * anything nondeterministic. */
    pipeline_u8 sigA[PIPELINE_SCHNORR_SIG_SIZE];
    pipeline_u8 sigB[PIPELINE_SCHNORR_SIG_SIZE];
    int okA = pipeline_schnorr_sign(kSchnorrMessageZero, kSchnorrPrivkey, sigA);
    int okB = pipeline_schnorr_sign(kSchnorrMessageZero, kSchnorrPrivkey, sigB);

    check(okA && okB && memcmp(sigA, sigB, PIPELINE_SCHNORR_SIG_SIZE) == 0,
          "pipeline_schnorr_sign is deterministic across repeated calls with the same inputs");
}

/*
 * Spec #43 sub-issue #46: the baked public point P = d*G (secp256k1_baked.h,
 * generated by tools/gen_secp256k1_baked.py from the same TEST_PRIVKEY_HEX/
 * kSchnorrPrivkey used throughout this file) must match a reference-computed
 * d*G. pipeline_secp256k1_point_mul_base() -- the very runtime scalar
 * multiplication this sub-issue removes from pipeline_schnorr_sign's own
 * path -- is retained (still used by pipeline_schnorr_verify's internal
 * self-consistency check) and serves here purely as that reference oracle,
 * exactly mirroring how #44/#45 kept their naive reductions as differential-
 * test oracles after replacing them on the hot path. This is the required
 * host-test-seam proof that the baked P matches the reference EC math,
 * independent of (and in addition to) gen_secp256k1_baked.py's own build-
 * time validation against the same reference math.
 */
static void test_baked_public_point_matches_reference(void)
{
    static const pipeline_u8 kBakedPubkeyX[32] = PIPELINE_SECP256K1_BAKED_PUBKEY_X_BYTES;
    pipeline_secp256k1_num dPrime;
    pipeline_secp256k1_point referenceP;
    pipeline_u8 referenceXBytes[32];

    pipeline_secp256k1_num_from_bytes(kSchnorrPrivkey, &dPrime);
    pipeline_secp256k1_point_mul_base(&dPrime, &referenceP);
    pipeline_secp256k1_num_to_bytes(&referenceP.x, referenceXBytes);

    check(memcmp(kBakedPubkeyX, referenceXBytes, 32) == 0,
          "secp256k1_baked.h's baked P.x matches a reference-computed d*G "
          "(pipeline_secp256k1_point_mul_base) for the same private key");
    check((PIPELINE_SECP256K1_BAKED_PUBKEY_Y_IS_EVEN != 0) == (pipeline_secp256k1_point_y_is_even(&referenceP) != 0),
          "secp256k1_baked.h's baked Y_IS_EVEN parity flag matches the reference-computed d*G's "
          "actual y parity");

    /* Cross-file consistency: secp256k1_baked.h's baked P.x and
     * event_profile.h's PIPELINE_EVENT_PUBKEY_BYTES are generated by two
     * SEPARATE scripts (gen_secp256k1_baked.py, gen_event_profile.py) from
     * the same private key, and nothing else in this codebase ties them
     * together -- event_id.c writes the event's pubkey field from
     * PIPELINE_EVENT_PUBKEY_BYTES while schnorr_adapter.c hashes the baked
     * X, so if these two generated headers ever silently drifted apart
     * (wrong key file, stale build artifact, etc.) the emitted event's
     * declared pubkey and its actual signing key would disagree with no
     * build failure. */
    {
        static const pipeline_u8 kEventProfilePubkey[32] = PIPELINE_EVENT_PUBKEY_BYTES;
        check(memcmp(kBakedPubkeyX, kEventProfilePubkey, 32) == 0,
              "secp256k1_baked.h's baked P.x matches event_profile.h's PIPELINE_EVENT_PUBKEY_BYTES "
              "exactly -- the two separately-generated headers agree on the same public key");
    }
}

/*
 * Spec #43 sub-issue #46: pipeline_schnorr_sign's step 2 selects
 * d = dPrime or d = n - dPrime based on a BUILD-TIME constant
 * (PIPELINE_SECP256K1_BAKED_PUBKEY_Y_IS_EVEN). For THIS host build's key
 * (kSchnorrPrivkey = 3, whose P has EVEN y -- see
 * test_baked_public_point_matches_reference() above), that constant is 1,
 * so pipeline_schnorr_sign itself, as compiled here, only ever exercises
 * the d = dPrime branch -- the pipeline_secp256k1_scalar_negate() "else"
 * branch (schnorr_adapter.c) is dead code in THIS binary, never run by any
 * other test in this file. A real per-event key is equally likely to land
 * on either parity, so that branch's math must be proven correct some
 * other way: this test finds (by a small, deterministic, non-random
 * search) a private key whose P has ODD y, then reproduces step 2's exact
 * else-branch logic against it using only the runtime primitives
 * schnorr_adapter.c itself calls (pipeline_secp256k1_point_mul_base,
 * pipeline_secp256k1_point_y_is_even, pipeline_secp256k1_scalar_negate,
 * pipeline_secp256k1_scalar_in_range) -- proving the negate branch always
 * produces a valid, BIP-340-legal signing scalar, not just for whichever
 * parity this particular baked test key happens to have.
 */
static void test_odd_y_parity_negation_branch(void)
{
    pipeline_secp256k1_num dPrime, dNegated;
    pipeline_secp256k1_point p, pFromNegated;
    pipeline_u8 kb[32];
    pipeline_u8 xBytes[32], xFromNegatedBytes[32];
    int i, foundOdd;

    for (i = 0; i < 32; i++) {
        kb[i] = 0;
    }

    /* Search small increasing scalars starting at 1 for one whose P has an
     * odd y -- deterministic (not random), and terminates quickly: there
     * is no mathematical reason small d's would all share one parity, and
     * empirically d=6 is already the first one that qualifies (d=1..5 all
     * happen to have even y). */
    foundOdd = 0;
    for (i = 1; i < 64 && !foundOdd; i++) {
        kb[31] = (pipeline_u8)i;
        pipeline_secp256k1_num_from_bytes(kb, &dPrime);
        pipeline_secp256k1_point_mul_base(&dPrime, &p);
        if (!pipeline_secp256k1_point_y_is_even(&p)) {
            foundOdd = 1;
        }
    }
    check(foundOdd,
          "odd-y search: found a small private key whose P has odd y within the search bound "
          "(sanity check on the search itself, not on the negate branch)");
    if (!foundOdd) {
        return;
    }

    /* Reproduce schnorr_adapter.c step 2's exact else-branch logic
     * (d = n - d'), then prove it did its job: (n - d')*G must have EVEN
     * y (the whole point of the branch) and the SAME x coordinate as
     * d'*G (point negation only flips y, never x -- bytes(P) in the
     * signature is unaffected by which branch selected d, matching
     * BIP-340's keygen definition). */
    pipeline_secp256k1_scalar_negate(&dPrime, &dNegated);
    check(pipeline_secp256k1_scalar_in_range(&dNegated),
          "odd-y negation branch: n - d' is itself a valid scalar in [1, n-1]");

    pipeline_secp256k1_point_mul_base(&dNegated, &pFromNegated);
    check(pipeline_secp256k1_point_y_is_even(&pFromNegated),
          "odd-y negation branch: (n - d')*G has even y -- schnorr_adapter.c's else branch "
          "(pipeline_secp256k1_scalar_negate) genuinely fixes the parity it exists to fix, proven "
          "here since this host build's own baked key never exercises it (its P has even y already)");

    pipeline_secp256k1_num_to_bytes(&p.x, xBytes);
    pipeline_secp256k1_num_to_bytes(&pFromNegated.x, xFromNegatedBytes);
    check(memcmp(xBytes, xFromNegatedBytes, 32) == 0,
          "odd-y negation branch: (n - d')*G has the SAME x coordinate as d'*G -- bytes(P) is "
          "unaffected by which branch selected d, so BIP-340's tagged hashes see the same P "
          "either way");
}

/*
 * Fixed capture-time input vector shared by both capture tests below.
 * nonce16's expected value (0xDB3B) was computed independently with
 * Python's hashlib over the exact 12-byte big-endian concatenation
 * capture.h documents (osCount||globalTimer||rawStickX||rawStickY||
 * buttonMask = 11 22 33 44 55 66 77 88 0a f6 80 01), taking the first two
 * SHA-256 digest bytes -- NOT re-derived from this repo's own ported
 * sha256.c, so it genuinely pins pipeline_capture_build()'s nonce-hashing
 * contract rather than merely reflecting whatever the port happens to
 * compute.
 */
#define PIPELINE_TEST_CAPTURE_COURSE      4u
#define PIPELINE_TEST_CAPTURE_ACT         2u
#define PIPELINE_TEST_CAPTURE_COINS       50u
#define PIPELINE_TEST_CAPTURE_STAR_INDEX  12u
#define PIPELINE_TEST_CAPTURE_OS_COUNT    0x11223344u
#define PIPELINE_TEST_CAPTURE_GLOBAL_TIMER 0x55667788u
/* Mirrors the ROM glue's actual call shape at interact_star_or_key, which
 * passes gGlobalTimer for BOTH the `frames` argument and one of the nonce
 * hash inputs (see interaction.c's own comment on that reuse) -- this test
 * vector does the same rather than using two different values, so it
 * exercises the real call shape, not a hypothetical one. */
#define PIPELINE_TEST_CAPTURE_FRAMES      PIPELINE_TEST_CAPTURE_GLOBAL_TIMER
#define PIPELINE_TEST_CAPTURE_RAW_STICK_X 10u
#define PIPELINE_TEST_CAPTURE_RAW_STICK_Y 246u
#define PIPELINE_TEST_CAPTURE_BUTTONS     0x8001u
#define PIPELINE_TEST_CAPTURE_EXPECTED_NONCE16 0xDB3Bu

static void test_capture_build_known_answer(void)
{
    StarCapture capture;

    pipeline_capture_build((pipeline_u8) PIPELINE_TEST_CAPTURE_COURSE,
                            (pipeline_u8) PIPELINE_TEST_CAPTURE_ACT,
                            (pipeline_u8) PIPELINE_TEST_CAPTURE_COINS,
                            (pipeline_u32) PIPELINE_TEST_CAPTURE_FRAMES,
                            (pipeline_u8) PIPELINE_TEST_CAPTURE_STAR_INDEX,
                            (pipeline_u32) PIPELINE_TEST_CAPTURE_OS_COUNT,
                            (pipeline_u32) PIPELINE_TEST_CAPTURE_GLOBAL_TIMER,
                            (pipeline_u8) PIPELINE_TEST_CAPTURE_RAW_STICK_X,
                            (pipeline_u8) PIPELINE_TEST_CAPTURE_RAW_STICK_Y,
                            (pipeline_u16) PIPELINE_TEST_CAPTURE_BUTTONS,
                            &capture);

    check(capture.course == PIPELINE_TEST_CAPTURE_COURSE
              && capture.act == PIPELINE_TEST_CAPTURE_ACT
              && capture.coins == PIPELINE_TEST_CAPTURE_COINS
              && capture.frames == PIPELINE_TEST_CAPTURE_FRAMES
              && capture.keyId == PIPELINE_TEST_CAPTURE_STAR_INDEX,
          "pipeline_capture_build carries course/act/coins/frames/starIndex(keyId) through exactly");

    check(capture.nonce16 == PIPELINE_TEST_CAPTURE_EXPECTED_NONCE16,
          "pipeline_capture_build's nonce16 matches the independent Python-hashlib known-answer vector (0xDB3B)");
}

static void test_select_frames_real_course_elapsed(void)
{
    /* Real course (courseNum != PIPELINE_COURSE_NONE): elapsed-since-entry,
     * globalTimer - courseStartFrame. starIndex is irrelevant for this
     * case (unused by #112's two cases; #113 branches on it only when
     * courseNum == PIPELINE_COURSE_NONE). */
    pipeline_u32 frames = pipeline_select_frames((pipeline_u8) 9 /* some real course */,
                                                  (pipeline_u8) 0,
                                                  (pipeline_u32) 5000,
                                                  (pipeline_u32) 4700);

    check(frames == 300, "pipeline_select_frames: real course reports elapsed-since-control-gain frames (300)");
}

static void test_select_frames_real_course_at_entry_is_zero(void)
{
    /* Grabbed on the very frame control was gained: elapsed is legitimately
     * 0 here (a grab a frame later is > 0, per the spec's sentinel-safety
     * argument -- this case alone doesn't collide with the "no in-course
     * time" sentinel because it can never occur for a real grab). */
    pipeline_u32 frames = pipeline_select_frames((pipeline_u8) 1, (pipeline_u8) 0,
                                                  (pipeline_u32) 1000, (pipeline_u32) 1000);

    check(frames == 0, "pipeline_select_frames: real course at globalTimer == courseStartFrame reports 0");
}

static void test_select_frames_non_course_sentinel(void)
{
    /* courseNum == PIPELINE_COURSE_NONE and NOT a MIPS star index (3/4):
     * the 0 sentinel, regardless of globalTimer/courseStartFrame. */
    pipeline_u32 frames = pipeline_select_frames((pipeline_u8) PIPELINE_COURSE_NONE, (pipeline_u8) 0,
                                                  (pipeline_u32) 99999, (pipeline_u32) 100);

    check(frames == 0, "pipeline_select_frames: non-course grab (starIndex not 3/4) reports the 0 sentinel");
}

static void test_select_frames_mips_star_index_elapsed(void)
{
    /* #113: courseNum == PIPELINE_COURSE_NONE with starIndex 3 or 4 (MIPS
     * stars 1 & 2, STAR_INDEX_ACT_4/5) reports elapsed-since-basement-entry
     * -- globalTimer - courseStartFrame, reading the SAME courseStartFrame
     * parameter the real-course branch uses (level_update.c's warp_area()
     * re-snapshots sCourseStartFrame on the guarded LEVEL_CASTLE-area-3
     * transition; this helper doesn't care which entry it's timing from). */
    pipeline_u32 framesIdx3 = pipeline_select_frames((pipeline_u8) PIPELINE_COURSE_NONE,
                                                      (pipeline_u8) PIPELINE_STAR_INDEX_ACT_4,
                                                      (pipeline_u32) 5000, (pipeline_u32) 4600);
    pipeline_u32 framesIdx4 = pipeline_select_frames((pipeline_u8) PIPELINE_COURSE_NONE,
                                                      (pipeline_u8) PIPELINE_STAR_INDEX_ACT_5,
                                                      (pipeline_u32) 5000, (pipeline_u32) 4600);

    check(framesIdx3 == 400 && framesIdx4 == 400,
          "pipeline_select_frames: MIPS star indices (3/4) report elapsed-since-basement-entry frames (400)");
}

static void test_select_frames_non_mips_course_less_star_index_still_sentinel(void)
{
    /* Guard against over-broadening the new MIPS branch: a course-less grab
     * with a star index that is NOT 3 or 4 (e.g. a regular 1-8 act star
     * somehow grabbed outside a course, or the 100-coin/grand-star indices)
     * must still fall through to the 0 sentinel -- only starIndex 3/4
     * qualifies. Includes the immediate boundary neighbors (2 and 5) of the
     * new branch, where an off-by-one would most likely hide. */
    pipeline_u32 framesIdx0 = pipeline_select_frames((pipeline_u8) PIPELINE_COURSE_NONE, (pipeline_u8) 0,
                                                      (pipeline_u32) 5000, (pipeline_u32) 4600);
    pipeline_u32 framesIdx2 = pipeline_select_frames((pipeline_u8) PIPELINE_COURSE_NONE, (pipeline_u8) 2,
                                                      (pipeline_u32) 5000, (pipeline_u32) 4600);
    pipeline_u32 framesIdx5 = pipeline_select_frames((pipeline_u8) PIPELINE_COURSE_NONE, (pipeline_u8) 5,
                                                      (pipeline_u32) 5000, (pipeline_u32) 4600);
    pipeline_u32 framesIdx6 = pipeline_select_frames((pipeline_u8) PIPELINE_COURSE_NONE, (pipeline_u8) 6,
                                                      (pipeline_u32) 5000, (pipeline_u32) 4600);

    check(framesIdx0 == 0 && framesIdx2 == 0 && framesIdx5 == 0 && framesIdx6 == 0,
          "pipeline_select_frames: course-less non-MIPS star indices (incl. boundary 2/5) still report the 0 sentinel");
}

static void test_capture_matches_host_build_event(void)
{
    /* Path A: the SAME two calls the ROM's real capture glue at
     * interact_star_or_key makes -- pipeline_capture_build() then
     * build_event() -- using this test's fixed input vector in place of
     * live N64 values. */
    StarCapture capturedViaGlue;
    BuiltEvent eventFromGlue;
    int buildOkA;

    /* Path B: a StarCapture assembled by hand for the "same run" (same
     * course/act/coins/frames, and the SAME known-answer nonce16 --
     * standing in for "the host tool's output for the same
     * course/act/coins/frames/nonce", per sub-issue #31's acceptance
     * criteria), then build_event() again. */
    StarCapture capturedByHand;
    BuiltEvent eventFromHand;
    int buildOkB;

    pipeline_capture_build((pipeline_u8) PIPELINE_TEST_CAPTURE_COURSE,
                            (pipeline_u8) PIPELINE_TEST_CAPTURE_ACT,
                            (pipeline_u8) PIPELINE_TEST_CAPTURE_COINS,
                            (pipeline_u32) PIPELINE_TEST_CAPTURE_FRAMES,
                            (pipeline_u8) PIPELINE_TEST_CAPTURE_STAR_INDEX,
                            (pipeline_u32) PIPELINE_TEST_CAPTURE_OS_COUNT,
                            (pipeline_u32) PIPELINE_TEST_CAPTURE_GLOBAL_TIMER,
                            (pipeline_u8) PIPELINE_TEST_CAPTURE_RAW_STICK_X,
                            (pipeline_u8) PIPELINE_TEST_CAPTURE_RAW_STICK_Y,
                            (pipeline_u16) PIPELINE_TEST_CAPTURE_BUTTONS,
                            &capturedViaGlue);
    buildOkA = build_event(&capturedViaGlue, kBuildEventPrivkey, &eventFromGlue);

    capturedByHand.course  = (pipeline_u8) PIPELINE_TEST_CAPTURE_COURSE;
    capturedByHand.act     = (pipeline_u8) PIPELINE_TEST_CAPTURE_ACT;
    capturedByHand.coins   = (pipeline_u8) PIPELINE_TEST_CAPTURE_COINS;
    capturedByHand.frames  = (pipeline_u32) PIPELINE_TEST_CAPTURE_FRAMES;
    capturedByHand.keyId   = (pipeline_u8) PIPELINE_TEST_CAPTURE_STAR_INDEX;
    capturedByHand.nonce16 = (pipeline_u16) PIPELINE_TEST_CAPTURE_EXPECTED_NONCE16;
    buildOkB = build_event(&capturedByHand, kBuildEventPrivkey, &eventFromHand);

    check(buildOkA != 0 && buildOkB != 0,
          "build_event succeeds for both the capture-glue path and the hand-built StarCapture path");

    /* The memcmp-based checks below only prove build_event is a (deterministic)
     * function of its StarCapture argument -- they can't fail by construction
     * when both paths are handed field-identical StarCaptures. To actually pin
     * down what "byte-identical to the host tool's output for the same
     * course/act/coins/frames/nonce" (sub-issue #31's acceptance criteria)
     * means at the wire level, check eventFromGlue.packed_payload's bytes
     * directly against this vector's literal expected values, at the offsets
     * format_descriptor.h independently generates from
     * src/pipeline/format_descriptor.json (not from pipeline_pack.c itself). */
    if (buildOkA) {
        int fieldsOk =
            eventFromGlue.packed_payload[PIPELINE_FMT_OFF_FORMAT_TAG] == (pipeline_u8)PIPELINE_FMT_TAG_VALUE &&
            eventFromGlue.packed_payload[PIPELINE_FMT_OFF_COURSE] == PIPELINE_TEST_CAPTURE_COURSE &&
            eventFromGlue.packed_payload[PIPELINE_FMT_OFF_ACT] == PIPELINE_TEST_CAPTURE_ACT &&
            eventFromGlue.packed_payload[PIPELINE_FMT_OFF_COINS] == PIPELINE_TEST_CAPTURE_COINS &&
            eventFromGlue.packed_payload[PIPELINE_FMT_OFF_FRAMES + 0] == 0x55 &&
            eventFromGlue.packed_payload[PIPELINE_FMT_OFF_FRAMES + 1] == 0x66 &&
            eventFromGlue.packed_payload[PIPELINE_FMT_OFF_FRAMES + 2] == 0x77 &&
            eventFromGlue.packed_payload[PIPELINE_FMT_OFF_FRAMES + 3] == 0x88 &&
            eventFromGlue.packed_payload[PIPELINE_FMT_OFF_NONCE16 + 0] == 0xDB &&
            eventFromGlue.packed_payload[PIPELINE_FMT_OFF_NONCE16 + 1] == 0x3B &&
            eventFromGlue.packed_payload[PIPELINE_FMT_OFF_KEY_ID] == PIPELINE_TEST_CAPTURE_STAR_INDEX;

        check(fieldsOk,
              "capture-glue path's packed_payload bytes match this vector's literal expected values "
              "at format_descriptor.h's independently-generated field offsets");
    }

    check(buildOkA && buildOkB
              && memcmp(eventFromGlue.packed_payload, eventFromHand.packed_payload,
                         PIPELINE_BUILT_PAYLOAD_SIZE) == 0,
          "byte-identity: capture-glue path's packed_payload == hand-built-StarCapture path's packed_payload "
          "for the same course/act/coins/frames/nonce");

    check(buildOkA && buildOkB
              && memcmp(eventFromGlue.qr_bitmaps[0], eventFromHand.qr_bitmaps[0],
                         PIPELINE_BUILT_QR_BITMAP_SIZE) == 0,
          "byte-identity: capture-glue path's qr_bitmap == hand-built-StarCapture path's qr_bitmap "
          "for the same course/act/coins/frames/nonce");
}

/*
 * test_qr_display_state_machine: the shared qr_display state machine's PURE
 * core (spec #24, sub-issue #33) -- see this file's header comment. Drives
 * ONE QrDisplayState through a synthetic input sequence and asserts all
 * four acceptance-critical behaviors.
 */
static void test_qr_display_state_machine(void)
{
    StarCapture capture;
    BuiltEvent event;
    int buildOk;
    QrDisplayState state;
    int i;
    int dismissed;
    int anyNonZero;
    int allZero;

    capture.course  = 1;
    capture.act     = 1;
    capture.coins   = 8;
    capture.frames  = 0x11223344u;
    capture.nonce16 = 0x1234;
    capture.keyId   = 0;

    buildOk = build_event(&capture, kBuildEventPrivkey, &event);
    check(buildOk != 0, "qr_display: build_event succeeds for the display test's StarCapture");
    if (!buildOk) {
        return;
    }

    /* Sanity: the bitmap under test is not already all-zero, so the erase
     * assertion below (c) is actually meaningful. */
    anyNonZero = 0;
    for (i = 0; i < PIPELINE_BUILT_QR_BITMAP_SIZE; i++) {
        if (event.qr_bitmaps[0][i] != 0) {
            anyNonZero = 1;
            break;
        }
    }
    check(anyNonZero, "qr_display: the built qr_bitmap under test is not already all-zero");

    qr_display_init(&state);
    check(!qr_display_is_active(&state), "qr_display: freshly-initialized state is not active");

    check(qr_display_present(&state, event.qr_bitmaps[0]) != 0,
          "qr_display: present() succeeds on a fresh state");
    check(qr_display_is_active(&state), "qr_display: state is active immediately after present()");
    check(memcmp(state.bitmap, event.qr_bitmaps[0], PIPELINE_BUILT_QR_BITMAP_SIZE) == 0,
          "qr_display: presented state holds a copy of the bitmap");

    /* (a) holding A from the dance (the same press that triggered it,
     * never yet released) does NOT dismiss, no matter how long it's held. */
    for (i = 0; i < 10; i++) {
        check(qr_display_update(&state, 1) == 0,
              "qr_display: holding A with no prior release never dismisses");
    }
    check(qr_display_is_active(&state), "qr_display: still active after holding A with no release");

    /* (b) release-then-press held for QR_DISPLAY_MIN_HOLD_FRAMES
     * consecutive frames DOES dismiss -- not a single frame sooner. */
    check(qr_display_update(&state, 0) == 0, "qr_display: a release frame itself never dismisses");
    for (i = 1; i < QR_DISPLAY_MIN_HOLD_FRAMES; i++) {
        check(qr_display_update(&state, 1) == 0,
              "qr_display: a fresh press held under the minimum frame count doesn't dismiss yet");
    }
    dismissed = qr_display_update(&state, 1);
    check(dismissed != 0,
          "qr_display: release-then-press held for QR_DISPLAY_MIN_HOLD_FRAMES dismisses");
    check(!qr_display_is_active(&state), "qr_display: state is no longer active after dismissal");

    /* (c) after dismiss, the held bitmap buffer is erased (all-zero). */
    allZero = 1;
    for (i = 0; i < PIPELINE_BUILT_QR_BITMAP_SIZE; i++) {
        if (state.bitmap[i] != 0) {
            allZero = 0;
            break;
        }
    }
    check(allZero, "qr_display: bitmap is memset-erased (all-zero) after dismissal");

    /* (d) a re-summon attempt (present() again on the SAME, already-
     * dismissed state) is rejected -- the never-re-summonable invariant. */
    check(qr_display_present(&state, event.qr_bitmaps[0]) == 0,
          "qr_display: present() after a dismissal on the same state is rejected "
          "(never re-summonable)");
    check(!qr_display_is_active(&state), "qr_display: a rejected present() leaves the state inactive");
}

/*
 * Field-reduction differential sweep + operation-count proxy (spec #43
 * sub-issue #44). Establishes the two proof mechanisms this spec's later
 * sub-issues reuse -- see secp256k1.h's header comment on
 * pipeline_secp256k1_fe_mul_fast/_reference/_reset_op_count/_get_op_count.
 *
 * Deterministic PRNG (xorshift32), seeded by a fixed literal: a failure
 * reproduces exactly by re-running with that same literal seed -- no
 * dependency on system time/entropy.
 */
static pipeline_u32 g_sweep_rng_state;

static void sweep_rng_seed(pipeline_u32 seed)
{
    g_sweep_rng_state = seed ? seed : 1u; /* xorshift32 must never start at 0 */
}

static pipeline_u32 sweep_rng_next(void)
{
    pipeline_u32 x = g_sweep_rng_state;
    x ^= (pipeline_u32)(x << 13);
    x ^= (x >> 17);
    x ^= (pipeline_u32)(x << 5);
    g_sweep_rng_state = x;
    return x;
}

/* Fills all 32 bytes with PRNG output and builds the num via the same
 * public byte<->num boundary every other caller in this codebase must use
 * (see secp256k1.c's own header comment on never assuming a particular
 * word order) -- deliberately NOT reduced below p first: num_mul's wide
 * product is well-defined (and the fast/reference reductions must agree)
 * for any two arbitrary 256-bit values, not just already-canonical field
 * elements, so leaving the full [0, 2^256) range in play is a strictly
 * stronger sweep. */
static void sweep_random_num(pipeline_secp256k1_num *out)
{
    pipeline_u8 bytes[PIPELINE_SECP256K1_BYTES];
    int i;
    for (i = 0; i < PIPELINE_SECP256K1_BYTES; i += 4) {
        pipeline_u32 word = sweep_rng_next();
        bytes[i + 0] = (pipeline_u8)((word >> 24) & 0xFFu);
        bytes[i + 1] = (pipeline_u8)((word >> 16) & 0xFFu);
        bytes[i + 2] = (pipeline_u8)((word >> 8) & 0xFFu);
        bytes[i + 3] = (pipeline_u8)(word & 0xFFu);
    }
    pipeline_secp256k1_num_from_bytes(bytes, out);
}

/*
 * Twin of sweep_random_num above, biased toward the top of the
 * [0, 2^256) range (spec #43 sub-issue #45). A uniformly random 256-bit
 * value is virtually always < the curve order n (n = 2^256 - c, c < 2^129,
 * so P(uniform random >= n) ~ 2^-127) -- meaning test_scalar_differential_
 * sweep()'s scalar_reduce coverage, if it only drew from
 * sweep_random_num(), would almost never actually exercise
 * scalar_reduce_wide's fold-and-subtract path (every reduction would take
 * the "already < n, nothing to fold away" shortcut), proving little beyond
 * "reducing an already-reduced value is a no-op on both paths". Forcing
 * the top 17 bytes (136 bits) to 0xFF guarantees the result is
 * >= 2^256 - 2^120, comfortably >= n, so every draw from this function
 * genuinely needs (and exercises) the fold rounds and the final
 * conditional-subtract loop. test_scalar_differential_sweep() draws from
 * both this and the plain uniform generator so the sweep covers both the
 * "no reduction needed" and "reduction needed" shapes.
 */
static void sweep_random_num_biased_high(pipeline_secp256k1_num *out)
{
    pipeline_u8 bytes[PIPELINE_SECP256K1_BYTES];
    int i;
    for (i = 0; i < PIPELINE_SECP256K1_BYTES; i += 4) {
        pipeline_u32 word = sweep_rng_next();
        bytes[i + 0] = (pipeline_u8)((word >> 24) & 0xFFu);
        bytes[i + 1] = (pipeline_u8)((word >> 16) & 0xFFu);
        bytes[i + 2] = (pipeline_u8)((word >> 8) & 0xFFu);
        bytes[i + 3] = (pipeline_u8)(word & 0xFFu);
    }
    for (i = 0; i < 17; i++) {
        bytes[i] = 0xFF;
    }
    pipeline_secp256k1_num_from_bytes(bytes, out);
}

#define FIELD_MUL_SWEEP_ITERATIONS 4000
#define FIELD_MUL_SWEEP_SEED 0xC0FFEE12u

/* Checks one (a, b) pair through both reduction paths, updating *allMatch/
 * *firstMismatch (index -1 means "not yet set") the same way the random
 * sweep loop does -- shared so the pinned edge vectors below and the
 * random sweep report failures identically. */
static void field_mul_differential_check_one(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b,
                                              int index, int *allMatch, int *firstMismatch)
{
    pipeline_secp256k1_num fast, reference;

    pipeline_secp256k1_fe_mul_fast(a, b, &fast);
    pipeline_secp256k1_fe_mul_reference(a, b, &reference);
    if (memcmp(&fast, &reference, sizeof(fast)) != 0) {
        *allMatch = 0;
        if (*firstMismatch < 0) {
            *firstMismatch = index;
        }
    }
}

static void test_field_mul_differential_sweep(void)
{
    int i;
    int allMatch = 1;
    int firstMismatch = -1;

    /* Pinned edge vectors: uniform random sampling below has ~0 chance of
     * ever hitting the boundary cases where fe_reduce_wide's fold-width
     * bookkeeping would actually be exercised at its limits (see that
     * function's header comment for the bounds these are meant to probe):
     * zero, one, the two operands both at their max representable 256-bit
     * value (2^256-1, driving hi close to its own max in num_mul's
     * product), and both operands at p-1 (the max canonical field
     * element, product close to (p-1)^2). */
    {
        pipeline_secp256k1_num zero, one, maxVal, pMinusOne;
        int edgeAllMatch = 1;
        int unusedFirstMismatch = -1;
        static const pipeline_u8 kZeroBytes[PIPELINE_SECP256K1_BYTES] = {0};
        static const pipeline_u8 kOneBytes[PIPELINE_SECP256K1_BYTES] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        };
        static const pipeline_u8 kMaxBytes[PIPELINE_SECP256K1_BYTES] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        };
        /* p - 1 = 2^256 - 2^32 - 978, secp256k1 p = 2^256 - 2^32 - 977. In
         * big-endian bytes: 24 bytes of 0xFF (the top 192 bits, words
         * w7..w2, all set), then word1 = 0xFFFFFFFE, then word0 =
         * 0xFFFFFC2E -- cross-checked directly against kFieldP in
         * secp256k1.c (word1 = 0xFFFFFFFE, word0 = 0xFFFFFC2F, i.e.
         * exactly one less in the bottom word) AND independently against
         * Python: (2**256 - 2**32 - 977 - 1).to_bytes(32, 'big'). */
        static const pipeline_u8 kPMinusOneBytes[PIPELINE_SECP256K1_BYTES] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2E,
        };

        pipeline_secp256k1_num_from_bytes(kZeroBytes, &zero);
        pipeline_secp256k1_num_from_bytes(kOneBytes, &one);
        pipeline_secp256k1_num_from_bytes(kMaxBytes, &maxVal);
        pipeline_secp256k1_num_from_bytes(kPMinusOneBytes, &pMinusOne);

        /* Edge vectors don't use the sweep's index-based first-mismatch
         * tracking (every vector here would collide on "not yet set");
         * edgeAllMatch/unusedFirstMismatch are a scratch pair local to
         * this block, checked collectively below. */
        field_mul_differential_check_one(&zero, &zero, 0, &edgeAllMatch, &unusedFirstMismatch);
        field_mul_differential_check_one(&zero, &maxVal, 0, &edgeAllMatch, &unusedFirstMismatch);
        field_mul_differential_check_one(&one, &maxVal, 0, &edgeAllMatch, &unusedFirstMismatch);
        field_mul_differential_check_one(&maxVal, &maxVal, 0, &edgeAllMatch, &unusedFirstMismatch);
        field_mul_differential_check_one(&pMinusOne, &pMinusOne, 0, &edgeAllMatch, &unusedFirstMismatch);
        field_mul_differential_check_one(&one, &one, 0, &edgeAllMatch, &unusedFirstMismatch);

        allMatch = edgeAllMatch;
    }
    check(allMatch, "field multiply differential sweep: fast reduction matches the naive reference "
                     "on pinned edge vectors (0, 1, 2^256-1, (p-1)^2)");

    allMatch = 1;
    firstMismatch = -1;
    sweep_rng_seed(FIELD_MUL_SWEEP_SEED);
    for (i = 0; i < FIELD_MUL_SWEEP_ITERATIONS; i++) {
        pipeline_secp256k1_num a, b;

        sweep_random_num(&a);
        sweep_random_num(&b);
        field_mul_differential_check_one(&a, &b, i, &allMatch, &firstMismatch);
    }

    if (!allMatch) {
        printf("  field_mul_differential_sweep: first mismatch at iteration %d "
               "(seed 0x%08lX, %d iterations) -- reproduce exactly with these constants\n",
               firstMismatch, (unsigned long)FIELD_MUL_SWEEP_SEED, FIELD_MUL_SWEEP_ITERATIONS);
    }
    check(allMatch,
          "field multiply differential sweep: fast field-specialized reduction matches the "
          "retained naive-reduction reference over 4000 seeded random 256-bit operand pairs");
}

/* Draws a canonical nonzero field element (0 < a < p) via rejection
 * sampling on sweep_random_num() above -- fe_inv requires a nonzero
 * field element, unlike sweep_random_num()'s own arbitrary-256-bit-
 * value contract (see that function's header comment). p is within 2^32+977
 * of 2^256, so the reject rate is astronomically small; this loop is a
 * correctness safeguard, not a practical perf concern. */
static void field_test_random_nonzero_field_element(pipeline_secp256k1_num *out)
{
    for (;;) {
        sweep_random_num(out);
        if (!pipeline_secp256k1_num_is_zero(out) && pipeline_secp256k1_num_is_valid_field_element(out)) {
            return;
        }
    }
}

/*
 * Field-inversion differential sweep (spec #43 sub-issue #48). Same seeded-
 * xorshift32-PRNG/differential-check shape test_field_mul_differential_
 * sweep() above established for #44, but over
 * pipeline_secp256k1_fe_inv_fast (the addition-chain path) versus
 * pipeline_secp256k1_fe_inv_reference (the retained naive full-256-bit
 * Fermat exponentiation path) -- see secp256k1.h's header comment on both.
 * Beyond "fast == reference", each draw also checks the TRUE modular-
 * inverse property directly (a * inv(a) = 1 mod p), via
 * pipeline_secp256k1_fe_mul_reference (the naive, independently-trusted
 * multiplication path -- deliberately not fe_mul_fast, so this check does
 * not depend on the fast multiply also being correct) -- issue #48's
 * acceptance criterion requires the fast inverse to be "identical to the
 * Fermat result", and this is the direct proof that the Fermat result
 * itself (and therefore the fast result, once shown equal to it) really is
 * a modular inverse, not just "fast agrees with reference" alone.
 */
#define FIELD_INV_SWEEP_ITERATIONS 4000
#define FIELD_INV_SWEEP_SEED 0xFEEDFACEu

static void test_field_inv_differential_sweep(void)
{
    int i;
    int allMatch = 1;
    int firstMismatch = -1;
    int allTrueInverse = 1;
    int firstNonInverse = -1;
    pipeline_secp256k1_num one;
    static const pipeline_u8 kOneBytes[PIPELINE_SECP256K1_BYTES] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };

    pipeline_secp256k1_num_from_bytes(kOneBytes, &one);

    /* Pinned edge vectors: 1 (its own inverse) and p-1 (also its own
     * inverse, since (p-1)^2 = p^2 - 2p + 1 = 1 mod p) -- both boundary
     * cases uniform random sampling would essentially never hit. */
    {
        pipeline_secp256k1_num pMinusOne;
        static const pipeline_u8 kPMinusOneBytes[PIPELINE_SECP256K1_BYTES] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2E,
        };
        pipeline_secp256k1_num fast, reference, product;
        int edgeAllMatch = 1;
        int edgeAllTrueInverse = 1;

        pipeline_secp256k1_num_from_bytes(kPMinusOneBytes, &pMinusOne);

        pipeline_secp256k1_fe_inv_fast(&one, &fast);
        pipeline_secp256k1_fe_inv_reference(&one, &reference);
        if (memcmp(&fast, &reference, sizeof(fast)) != 0) {
            printf("  field_inv_differential_sweep: edge vector 1 -- fast/reference mismatch\n");
            edgeAllMatch = 0;
        }
        pipeline_secp256k1_fe_mul_reference(&one, &fast, &product);
        if (memcmp(&product, &one, sizeof(product)) != 0) {
            printf("  field_inv_differential_sweep: edge vector 1 -- fast result is not a true inverse\n");
            edgeAllTrueInverse = 0;
        }

        pipeline_secp256k1_fe_inv_fast(&pMinusOne, &fast);
        pipeline_secp256k1_fe_inv_reference(&pMinusOne, &reference);
        if (memcmp(&fast, &reference, sizeof(fast)) != 0) {
            printf("  field_inv_differential_sweep: edge vector p-1 -- fast/reference mismatch\n");
            edgeAllMatch = 0;
        }
        pipeline_secp256k1_fe_mul_reference(&pMinusOne, &fast, &product);
        if (memcmp(&product, &one, sizeof(product)) != 0) {
            printf("  field_inv_differential_sweep: edge vector p-1 -- fast result is not a true inverse\n");
            edgeAllTrueInverse = 0;
        }

        allMatch = edgeAllMatch;
        allTrueInverse = edgeAllTrueInverse;
    }
    check(allMatch, "field inversion differential sweep: fast addition-chain inversion matches the "
                     "naive Fermat-exponentiation reference on pinned edge vectors (1, p-1)");
    check(allTrueInverse, "field inversion differential sweep: fast inversion is the TRUE modular "
                           "inverse (a * inv(a) = 1 mod p) on pinned edge vectors (1, p-1)");

    allMatch = 1;
    firstMismatch = -1;
    allTrueInverse = 1;
    firstNonInverse = -1;
    sweep_rng_seed(FIELD_INV_SWEEP_SEED);
    for (i = 0; i < FIELD_INV_SWEEP_ITERATIONS; i++) {
        pipeline_secp256k1_num a, fast, reference, product;

        field_test_random_nonzero_field_element(&a);

        pipeline_secp256k1_fe_inv_fast(&a, &fast);
        pipeline_secp256k1_fe_inv_reference(&a, &reference);
        if (memcmp(&fast, &reference, sizeof(fast)) != 0) {
            allMatch = 0;
            if (firstMismatch < 0) {
                firstMismatch = i;
            }
        }

        pipeline_secp256k1_fe_mul_reference(&a, &fast, &product);
        if (memcmp(&product, &one, sizeof(product)) != 0) {
            allTrueInverse = 0;
            if (firstNonInverse < 0) {
                firstNonInverse = i;
            }
        }
    }

    if (!allMatch) {
        printf("  field_inv_differential_sweep: first mismatch at iteration %d "
               "(seed 0x%08lX, %d iterations) -- reproduce exactly with these constants\n",
               firstMismatch, (unsigned long)FIELD_INV_SWEEP_SEED, FIELD_INV_SWEEP_ITERATIONS);
    }
    check(allMatch,
          "field inversion differential sweep: fast addition-chain inversion matches the retained "
          "naive Fermat-exponentiation reference over 4000 seeded random nonzero field elements");

    if (!allTrueInverse) {
        printf("  field_inv_differential_sweep: first non-inverse product at iteration %d "
               "(seed 0x%08lX, %d iterations) -- reproduce exactly with these constants\n",
               firstNonInverse, (unsigned long)FIELD_INV_SWEEP_SEED, FIELD_INV_SWEEP_ITERATIONS);
    }
    check(allTrueInverse,
          "field inversion differential sweep: the fast inverse is the TRUE modular inverse "
          "(a * inv(a) = 1 mod p, checked via the independently-trusted naive multiply) over the "
          "same 4000 seeded random nonzero field elements");
}

/*
 * Scalar (mod n) differential sweep (spec #43 sub-issue #45). Reuses the
 * same seeded-xorshift32-PRNG/sweep_random_num()/differential-check
 * shape test_field_mul_differential_sweep() above established for #44 --
 * see that function's header comment for the rationale (arbitrary 256-bit
 * values, not pre-reduced ones, since the fast/reference reductions must
 * agree for any input, not just already-canonical ones). Covers both
 * pipeline_secp256k1_scalar_reduce (a single 256-bit value reduced mod n --
 * the shape the BIP-340 nonce k and challenge e reduction actually uses)
 * and pipeline_secp256k1_scalar_mul (which internally forms a full 512-bit
 * product before reducing -- the shape s = (k + e*d) mod n's multiply
 * uses, and the one that actually exercises scalar_reduce_wide's fold
 * rounds against values anywhere near their full width).
 */
#define SCALAR_SWEEP_ITERATIONS 4000
#define SCALAR_SWEEP_SEED 0x5CA1AB1Eu

static void scalar_reduce_differential_check_one(const pipeline_secp256k1_num *a, int index, int *allMatch, int *firstMismatch)
{
    pipeline_secp256k1_num fast, reference;

    pipeline_secp256k1_scalar_reduce_fast(a, &fast);
    pipeline_secp256k1_scalar_reduce_reference(a, &reference);
    if (memcmp(&fast, &reference, sizeof(fast)) != 0) {
        *allMatch = 0;
        if (*firstMismatch < 0) {
            *firstMismatch = index;
        }
    }
}

static void scalar_mul_differential_check_one(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b,
                                               int index, int *allMatch, int *firstMismatch)
{
    pipeline_secp256k1_num fast, reference;

    pipeline_secp256k1_scalar_mul_fast(a, b, &fast);
    pipeline_secp256k1_scalar_mul_reference(a, b, &reference);
    if (memcmp(&fast, &reference, sizeof(fast)) != 0) {
        *allMatch = 0;
        if (*firstMismatch < 0) {
            *firstMismatch = index;
        }
    }
}

static void test_scalar_differential_sweep(void)
{
    int i;
    int allMatch;
    int firstMismatch;

    /* Pinned edge vectors: zero, one, the curve order's own max
     * representable value (2^256-1) and n-1 (the max canonical scalar),
     * squared/multiplied against themselves and each other -- same spirit
     * as the field sweep's edge vectors above, probing scalar_reduce_wide's
     * fold-round bookkeeping at its limits rather than relying on uniform
     * random sampling to ever land there. */
    {
        pipeline_secp256k1_num zero, one, maxVal, nMinusOne;
        int edgeAllMatch = 1;
        int edgeFirstMismatch = -1;
        static const pipeline_u8 kZeroBytes[PIPELINE_SECP256K1_BYTES] = {0};
        static const pipeline_u8 kOneBytes[PIPELINE_SECP256K1_BYTES] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        };
        static const pipeline_u8 kMaxBytes[PIPELINE_SECP256K1_BYTES] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        };
        /* n - 1, n = secp256k1 curve order = 0xFFFFFFFFFFFFFFFFFFFFFFFF
         * FFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 -- cross-checked
         * directly against kCurveN in secp256k1.c (same words, bottom byte
         * one less: ...D0364141 -> ...D0364140) AND independently against
         * Python:
         * (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - 1).to_bytes(32, 'big'). */
        static const pipeline_u8 kNMinusOneBytes[PIPELINE_SECP256K1_BYTES] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40,
        };

        pipeline_secp256k1_num_from_bytes(kZeroBytes, &zero);
        pipeline_secp256k1_num_from_bytes(kOneBytes, &one);
        pipeline_secp256k1_num_from_bytes(kMaxBytes, &maxVal);
        pipeline_secp256k1_num_from_bytes(kNMinusOneBytes, &nMinusOne);

        scalar_reduce_differential_check_one(&zero, 0, &edgeAllMatch, &edgeFirstMismatch);
        scalar_reduce_differential_check_one(&one, 0, &edgeAllMatch, &edgeFirstMismatch);
        scalar_reduce_differential_check_one(&maxVal, 0, &edgeAllMatch, &edgeFirstMismatch);
        scalar_reduce_differential_check_one(&nMinusOne, 0, &edgeAllMatch, &edgeFirstMismatch);

        scalar_mul_differential_check_one(&zero, &zero, 0, &edgeAllMatch, &edgeFirstMismatch);
        scalar_mul_differential_check_one(&zero, &maxVal, 0, &edgeAllMatch, &edgeFirstMismatch);
        scalar_mul_differential_check_one(&one, &maxVal, 0, &edgeAllMatch, &edgeFirstMismatch);
        scalar_mul_differential_check_one(&maxVal, &maxVal, 0, &edgeAllMatch, &edgeFirstMismatch);
        scalar_mul_differential_check_one(&nMinusOne, &nMinusOne, 0, &edgeAllMatch, &edgeFirstMismatch);
        scalar_mul_differential_check_one(&one, &one, 0, &edgeAllMatch, &edgeFirstMismatch);
        /* Mixed pairs, not just an operand against itself. */
        scalar_mul_differential_check_one(&maxVal, &nMinusOne, 0, &edgeAllMatch, &edgeFirstMismatch);
        scalar_mul_differential_check_one(&nMinusOne, &one, 0, &edgeAllMatch, &edgeFirstMismatch);

        /* edgeFirstMismatch isn't a meaningful index here (every call above
         * passes a fixed 0 -- there's no natural per-vector index for a
         * short, individually-named pinned list the way the random sweep
         * below has one), just a "did anything fail" latch shared with the
         * differential_check_one helpers' signature; edgeAllMatch alone
         * drives the actual assertion. */
        check(edgeAllMatch, "scalar (mod n) differential sweep: fast reduction/multiply matches the naive "
                             "reference on pinned edge vectors (0, 1, 2^256-1, n-1)");
    }

    allMatch = 1;
    firstMismatch = -1;
    sweep_rng_seed(SCALAR_SWEEP_SEED);
    for (i = 0; i < SCALAR_SWEEP_ITERATIONS; i++) {
        pipeline_secp256k1_num a;

        /* Alternate plain-uniform and biased-high draws (see
         * sweep_random_num_biased_high's header comment): uniform
         * alone would almost never land >= n, so half the iterations bias
         * toward the top of [0, 2^256) to actually exercise
         * scalar_reduce_wide's fold-and-subtract path, not just its
         * "already reduced" shortcut. */
        if (i & 1) {
            sweep_random_num_biased_high(&a);
        } else {
            sweep_random_num(&a);
        }
        scalar_reduce_differential_check_one(&a, i, &allMatch, &firstMismatch);
    }
    if (!allMatch) {
        printf("  scalar_reduce_differential_sweep: first mismatch at iteration %d "
               "(seed 0x%08lX, %d iterations) -- reproduce exactly with these constants\n",
               firstMismatch, (unsigned long)SCALAR_SWEEP_SEED, SCALAR_SWEEP_ITERATIONS);
    }
    check(allMatch,
          "scalar reduce differential sweep: fast curve-order-specialized reduction matches the "
          "retained naive-reduction reference over 4000 seeded random 256-bit values "
          "(half plain-uniform, half biased >= n to exercise the fold-and-subtract path)");

    allMatch = 1;
    firstMismatch = -1;
    sweep_rng_seed(SCALAR_SWEEP_SEED ^ 0xA5A5A5A5u);
    for (i = 0; i < SCALAR_SWEEP_ITERATIONS; i++) {
        pipeline_secp256k1_num a, b;

        sweep_random_num(&a);
        sweep_random_num(&b);
        scalar_mul_differential_check_one(&a, &b, i, &allMatch, &firstMismatch);
    }
    if (!allMatch) {
        printf("  scalar_mul_differential_sweep: first mismatch at iteration %d "
               "(seed 0x%08lX, %d iterations) -- reproduce exactly with these constants\n",
               firstMismatch, (unsigned long)(SCALAR_SWEEP_SEED ^ 0xA5A5A5A5u), SCALAR_SWEEP_ITERATIONS);
    }
    check(allMatch,
          "scalar multiply differential sweep: fast curve-order-specialized reduction matches the "
          "retained naive-reduction reference over 4000 seeded random 256-bit operand pairs "
          "(exercises the full 512-bit-product reduction shape s = (k + e*d) mod n's multiply uses)");
}

/*
 * Fixed-base comb k*G differential sweep + cache-budget assertion (spec
 * #43, sub-issue #47). Reuses the same seeded-xorshift32-PRNG/pinned-edge-
 * vectors shape #44/#45 established above, this time comparing
 * pipeline_secp256k1_point_mul_base (the fast path, now
 * point_mul_base_comb -- a table lookup per comb column) against
 * pipeline_secp256k1_point_mul_base_reference (the RETAINED naive
 * per-bit double-and-add, the same algorithm point_mul_base itself used
 * before this sub-issue) for the SAME k, asserting the two agree on the
 * full resulting affine point (x, y, and infinity-ness) -- not just x, so
 * a wrong-parity/sign table entry would be caught here too, exactly like
 * derive_and_validate()'s own point-vs-just-x distinction in
 * gen_secp256k1_baked.py.
 *
 * k here is drawn from sweep_random_num() (the plain uniform [0,
 * 2^256) generator #44 established), NOT reduced mod n first: both
 * point_mul_base and point_mul_base_reference are well-defined for ANY
 * 256-bit k (a plain double-and-add / comb evaluation of the integer k*G,
 * with no notion of "canonical scalar range" baked into either algorithm),
 * so this is the strictly stronger sweep, mirroring field_mul_differential_
 * check_one's own reasoning for the field-multiply sweep above.
 */
#define POINT_MUL_BASE_SWEEP_ITERATIONS 500
#define POINT_MUL_BASE_SWEEP_SEED 0xB16B00B5u

static int points_equal(const pipeline_secp256k1_point *a, const pipeline_secp256k1_point *b)
{
    if (a->infinity || b->infinity) {
        return a->infinity && b->infinity;
    }
    return memcmp(&a->x, &b->x, sizeof(a->x)) == 0 && memcmp(&a->y, &b->y, sizeof(a->y)) == 0;
}

static void point_mul_base_differential_check_one(const pipeline_secp256k1_num *k, int index, int *allMatch, int *firstMismatch)
{
    pipeline_secp256k1_point fast, reference;

    pipeline_secp256k1_point_mul_base(k, &fast);
    pipeline_secp256k1_point_mul_base_reference(k, &reference);
    if (!points_equal(&fast, &reference)) {
        *allMatch = 0;
        if (*firstMismatch < 0) {
            *firstMismatch = index;
        }
    }
}

static void test_point_mul_base_comb_differential_sweep(void)
{
    int i;
    int allMatch;
    int firstMismatch;

    /* Build-time/compile-time cache-budget assertion, re-checked here at
     * host-test time too (not just by kCombTableBudgetCheck's compile-time
     * negative-array-size trick in secp256k1.c, and not just by
     * gen_secp256k1_baked.py's own validate_comb_table() at generation
     * time): PIPELINE_SECP256K1_COMB_TABLE_BYTES (this generated header's
     * own accounting of kCombTable's size) must fit the VR4300's 8 KB data
     * cache. Printed so the chosen size is visible in a normal test run,
     * not just discoverable by reading the header. */
    printf("  comb table: COMB_D=%d, COMB_E=%d, %d entries, %d bytes (8 KB budget)\n",
           (int)PIPELINE_SECP256K1_COMB_D, (int)PIPELINE_SECP256K1_COMB_E,
           (int)PIPELINE_SECP256K1_COMB_TABLE_SIZE, (int)PIPELINE_SECP256K1_COMB_TABLE_BYTES);
    check(PIPELINE_SECP256K1_COMB_TABLE_BYTES > 0 &&
          PIPELINE_SECP256K1_COMB_TABLE_BYTES <= PIPELINE_SECP256K1_COMB_CACHE_BUDGET_BYTES,
          "comb table: PIPELINE_SECP256K1_COMB_TABLE_BYTES fits within PIPELINE_SECP256K1_COMB_CACHE_BUDGET_BYTES "
          "(the VR4300's 8 KB data cache budget)");

    /* Pinned edge vectors: zero (k*G undefined/infinity on both paths --
     * point_mul_core's own early-out and point_mul_base_comb's "every
     * column digit s is 0" case must agree), one, two, the highest bit
     * alone set, the lowest COMB_E bits alone set (exercises exactly row
     * i=0 of the comb decomposition and nothing else), and 2^256-1 (every
     * bit set, exercising every row/column of the comb decomposition at
     * once). */
    {
        pipeline_secp256k1_num zero, one, two, maxVal, highBit, lowSpan;
        int edgeAllMatch = 1;
        int edgeFirstMismatch = -1;
        static const pipeline_u8 kZeroBytes[PIPELINE_SECP256K1_BYTES] = {0};
        static const pipeline_u8 kOneBytes[PIPELINE_SECP256K1_BYTES] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        };
        static const pipeline_u8 kTwoBytes[PIPELINE_SECP256K1_BYTES] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        };
        static const pipeline_u8 kMaxBytes[PIPELINE_SECP256K1_BYTES] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        };
        /* bit 255 (the top bit) alone set. */
        static const pipeline_u8 kHighBitBytes[PIPELINE_SECP256K1_BYTES] = {
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };
        /* the bottom 43 bits (0x7FFFFFFFFFF) all set -- exactly row i=0's
         * span for COMB_D=6/COMB_E=43; a mismatch confined to this vector
         * alone would isolate a bug to row 0's basis point/table entries. */
        static const pipeline_u8 kLowSpanBytes[PIPELINE_SECP256K1_BYTES] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        };

        pipeline_secp256k1_num_from_bytes(kZeroBytes, &zero);
        pipeline_secp256k1_num_from_bytes(kOneBytes, &one);
        pipeline_secp256k1_num_from_bytes(kTwoBytes, &two);
        pipeline_secp256k1_num_from_bytes(kMaxBytes, &maxVal);
        pipeline_secp256k1_num_from_bytes(kHighBitBytes, &highBit);
        pipeline_secp256k1_num_from_bytes(kLowSpanBytes, &lowSpan);

        /* Distinct indices (0..5, one per vector below) rather than a
         * shared 0 -- unlike a bare pass/fail latch, edgeFirstMismatch here
         * can actually name WHICH pinned vector failed if one does. */
        point_mul_base_differential_check_one(&zero, 0, &edgeAllMatch, &edgeFirstMismatch);
        point_mul_base_differential_check_one(&one, 1, &edgeAllMatch, &edgeFirstMismatch);
        point_mul_base_differential_check_one(&two, 2, &edgeAllMatch, &edgeFirstMismatch);
        point_mul_base_differential_check_one(&maxVal, 3, &edgeAllMatch, &edgeFirstMismatch);
        point_mul_base_differential_check_one(&highBit, 4, &edgeAllMatch, &edgeFirstMismatch);
        point_mul_base_differential_check_one(&lowSpan, 5, &edgeAllMatch, &edgeFirstMismatch);

        if (!edgeAllMatch) {
            static const char *const kEdgeVectorNames[6] = {
                "zero", "one", "two", "2^256-1", "high-bit-only", "row-0-span-only",
            };
            printf("  point_mul_base_comb edge-vector sweep: first mismatch at vector %d (%s)\n",
                   edgeFirstMismatch,
                   (edgeFirstMismatch >= 0 && edgeFirstMismatch < 6) ? kEdgeVectorNames[edgeFirstMismatch] : "?");
        }
        check(edgeAllMatch,
              "fixed-base comb k*G differential sweep: fast comb table matches the naive "
              "double-and-add reference on pinned edge vectors (0, 1, 2, 2^256-1, "
              "high-bit-only, row-0-span-only)");
    }

    allMatch = 1;
    firstMismatch = -1;
    sweep_rng_seed(POINT_MUL_BASE_SWEEP_SEED);
    for (i = 0; i < POINT_MUL_BASE_SWEEP_ITERATIONS; i++) {
        pipeline_secp256k1_num k;

        sweep_random_num(&k);
        point_mul_base_differential_check_one(&k, i, &allMatch, &firstMismatch);
    }
    if (!allMatch) {
        printf("  point_mul_base_comb_differential_sweep: first mismatch at iteration %d "
               "(seed 0x%08lX, %d iterations) -- reproduce exactly with these constants\n",
               firstMismatch, (unsigned long)POINT_MUL_BASE_SWEEP_SEED, POINT_MUL_BASE_SWEEP_ITERATIONS);
    }
    check(allMatch,
          "fixed-base comb k*G differential sweep: fast comb table matches the retained naive "
          "double-and-add reference over 500 seeded random 256-bit scalars k");
}

/*
 * Host-side field-multiply / operation-count proxy (spec #43 sub-issue
 * #44's other required proof mechanism). Two independent assertions:
 *
 * (1) Per-multiply: the fast field reduction does dramatically fewer
 *     primitive word operations than the retained naive reference does
 *     for the exact same inputs -- the direct "pre-change baseline"
 *     comparison, since the naive reduce_wide_mod path IS what fe_mul
 *     used to be before this sub-issue (see
 *     pipeline_secp256k1_fe_mul_reference's header comment).
 * (2) Per-signature: a real BIP-340 signature's total op count stays
 *     within a small bound -- empirically measured (once, manually, during
 *     sub-issue #44's development, by temporarily forcing fe_mul back to
 *     the naive reduce_wide_mod path and re-running this same measurement)
 *     at ~283K ops with only the field path fast (scalar still naive at
 *     that point), versus ~28.0M ops with neither path fast -- a ~99x
 *     drop. That manual before/after comparison isn't itself re-derivable
 *     from this file (there is no "sign with the naive field path" entry
 *     point to call here), so the bound below is set with headroom over
 *     what's actually measured at the bottom of this function.
 *
 * (3)/(4) below (sub-issue #45) add the same fast-vs-naive comparison for
 *     the scalar (mod n) path, and re-measure the per-signature bound now
 *     that BOTH paths are fast: with the scalar path's own bit-serial
 *     division gone too, total signature op count drops only modestly
 *     further (~283K -> ~279K, measured), NOT dramatically -- because
 *     point_mul_base's k*G (256 double-and-add iterations, each several
 *     field multiplies) already dominates total signature cost once the
 *     field path alone is fast, and scalar reduction/multiplication (3
 *     calls per signature: reducing k, reducing e, computing e*d) was
 *     always a small fraction of that total even before this sub-issue.
 *     The scalar path's own large relative speedup (see (3) below, a
 *     >10x drop on the operation itself) is real and is sub-issue #45's
 *     acceptance criterion; it just isn't the dominant term in the
 *     whole-signature total until a later sub-issue (#46/#47) replaces
 *     k*G's double-and-add with a fixed-base comb table. Wall-clock time
 *     is deliberately not used here (it does not represent the target
 *     VR4300 -- see secp256k1.h's header comment).
 *
 * (5) Sub-issue #46 removed pipeline_schnorr_sign's OTHER point_mul_base
 *     call entirely (P = d'*G, now baked at build time -- see
 *     secp256k1_baked.h and test_baked_public_point_matches_reference()
 *     above), measured at the time at ~249K, down from ~279K.
 *
 * (6) Sub-issue #47 replaces pipeline_secp256k1_point_mul_base's OWN
 *     algorithm (used for #46's one remaining call, R = k'*G) with the
 *     fixed-base comb table (point_mul_base_comb) instead of the generic
 *     per-bit double-and-add (point_mul_core) #44-#46 left it running --
 *     see secp256k1.h's own header comment. This directly lowers signOps
 *     itself (no longer ~249K), so unlike #46 (which only removed a call
 *     entirely, leaving the remaining call's own cost unchanged), the
 *     self-proving reconstruction check below no longer applies: there is
 *     no "P's removed cost" left to reconstruct signOps + isolated-P-cost
 *     back up to; instead, this sub-issue's own proof is a direct fast-
 *     vs-naive comparison of pipeline_secp256k1_point_mul_base against
 *     the RETAINED naive reference (pipeline_secp256k1_point_mul_base_
 *     reference, the exact algorithm point_mul_base itself used before
 *     this sub-issue), isolated from signing entirely -- see below, and
 *     tools/pipeline_test/main.c's test_point_mul_base_comb_differential_
 *     sweep() for the correctness half of this sub-issue's proof.
 *
 * (7) Sub-issue #48 replaces fe_inv's own algorithm (used by jac_to_affine,
 *     the ONE field inversion a signature still runs -- see fe_inv's header
 *     comment in secp256k1.c): full 256-bit square-and-multiply Fermat
 *     exponentiation (fe_pow(a, p-2)) becomes the published fixed addition
 *     chain (255 squarings + 15 multiplications). Two direct proofs below,
 *     mirroring (6): a fast-vs-naive op-count comparison isolated from
 *     signing entirely (pipeline_secp256k1_fe_inv_fast vs _reference, for
 *     the same field element), and a check that a real signature performs
 *     exactly one inversion (pipeline_secp256k1_get_inversion_count()),
 *     proving the "at most one modular inversion per signature" acceptance
 *     criterion directly rather than inferring it from the total op count.
 */
static void test_field_op_count_proxy(void)
{
    pipeline_secp256k1_num a, b, out;
    unsigned long long fastOps, refOps;
    pipeline_u8 sig[PIPELINE_SCHNORR_SIG_SIZE];
    unsigned long long signOps;
    int signOk;

    sweep_rng_seed(0xA5A5A5A5u);
    sweep_random_num(&a);
    sweep_random_num(&b);

    pipeline_secp256k1_reset_op_count();
    pipeline_secp256k1_fe_mul_fast(&a, &b, &out);
    fastOps = pipeline_secp256k1_get_op_count();

    pipeline_secp256k1_reset_op_count();
    pipeline_secp256k1_fe_mul_reference(&a, &b, &out);
    refOps = pipeline_secp256k1_get_op_count();

    check(fastOps > 0 && refOps > 0, "op-count proxy: both field-multiply paths perform a nonzero number of counted operations");
    check(fastOps * 10 < refOps,
          "op-count proxy: the fast field multiply's operation count is more than 10x lower "
          "than the retained naive reference's, for the same operands");

    /* (3) Scalar path (sub-issue #45): same fast-vs-naive comparison as (1)
     * above, but for scalar_reduce (the shape k/e reduction uses) instead
     * of field multiply -- the direct proof that the scalar path itself
     * dropped its bit-serial division, independent of the whole-signature
     * bound in (4) below. */
    {
        pipeline_secp256k1_num scalarA, scalarFast, scalarRef;
        unsigned long long scalarFastOps, scalarRefOps;

        sweep_rng_seed(SCALAR_SWEEP_SEED);
        sweep_random_num(&scalarA);

        pipeline_secp256k1_reset_op_count();
        pipeline_secp256k1_scalar_reduce_fast(&scalarA, &scalarFast);
        scalarFastOps = pipeline_secp256k1_get_op_count();

        pipeline_secp256k1_reset_op_count();
        pipeline_secp256k1_scalar_reduce_reference(&scalarA, &scalarRef);
        scalarRefOps = pipeline_secp256k1_get_op_count();

        check(scalarFastOps > 0 && scalarRefOps > 0,
              "op-count proxy: both scalar-reduce paths perform a nonzero number of counted operations");
        check(scalarFastOps * 10 < scalarRefOps,
              "op-count proxy: the fast scalar (mod n) reduction's operation count is more than 10x "
              "lower than the retained naive reference's, for the same operand -- the scalar path's own "
              "cost dropping (sub-issue #45's acceptance criterion), independent of the field path");
    }

    pipeline_secp256k1_reset_op_count();
    signOk = pipeline_schnorr_sign(kSchnorrMessageZero, kSchnorrPrivkey, sig);
    signOps = pipeline_secp256k1_get_op_count();

    check(signOk != 0, "op-count proxy: the signature used to measure per-signature op count still succeeds");
    /* (7) Sub-issue #48's own direct per-signature proof: the signature just
     * measured above performs EXACTLY one field inversion (jac_to_affine's
     * conversion of R = k'*G -- P = d*G needs none, baked at build time by
     * sub-issue #46) -- directly proving spec #43's "at most one modular
     * inversion runs per signature" implementation decision via the
     * dedicated inversion counter, rather than inferring it from the total
     * op count. Asserted at exactly 1 (the stronger, more specific claim),
     * not merely "<= 1" -- a signature that ran zero inversions would be a
     * bug (R would never be converted to affine), not a pass. */
    check(pipeline_secp256k1_get_inversion_count() == 1ULL,
          "op-count proxy: a full BIP-340 signature performs exactly one field inversion "
          "(pipeline_secp256k1_get_inversion_count()) -- R = k'*G's Jacobian-to-affine conversion "
          "is the only one; P = d*G needs none, having been baked at build time (sub-issue #46)");
    /* 90,000 sits comfortably below the ~81,470 this function itself
     * measures below (printed nowhere, but reproducible: same fixed KAT
     * key/message/aux_rand every run), yet well BELOW #46's own ~249,450
     * measurement (P baked, k*G still generic double-and-add) -- so this
     * bound's job, like #46's own bound before it, is to catch #47
     * regressing (point_mul_base's comb path silently reverting to
     * point_mul_core) rather than merely to hold with headroom over
     * whatever the current number happens to be. */
    check(signOps < 90000ULL,
          "op-count proxy: a full BIP-340 signature's total primitive-word-op count stays under "
          "90,000 now that R = k'*G itself uses the fixed-base comb table instead of generic "
          "double-and-add (sub-issue #47) on top of P = d*G being baked at build time "
          "(sub-issue #46) -- measured ~81K; ~249K with #47 not yet landed (#44/#45/#46 only), "
          "~28.0M with none of #44/#45/#46/#47 landed, the original naive baseline -- see this "
          "function's header comment for the full before/after trace");

    /*
     * (6) Sub-issue #47's own direct proof: pipeline_secp256k1_point_mul_
     * base (now point_mul_base_comb) against the RETAINED naive reference
     * pipeline_secp256k1_point_mul_base_reference (point_mul_core, the
     * exact algorithm point_mul_base itself used before this sub-issue),
     * for the SAME scalar -- isolated from the rest of signing entirely,
     * exactly like (1)/(3) above isolate the field/scalar fast-vs-naive
     * comparisons from the whole-signature bound. k here is a full-width
     * (not small-integer) scalar, unlike kSchnorrPrivkey's d=3 -- see this
     * function's header comment point (5) for why d=3 specifically is an
     * atypically cheap double-and-add input (254 near-free leading-zero-bit
     * doublings) that would understate the naive path's true cost and so
     * understate the speedup this check is meant to demonstrate.
     */
    {
        pipeline_secp256k1_num k;
        pipeline_secp256k1_point fastPoint, referencePoint;
        unsigned long long pointFastOps, pointRefOps;

        sweep_rng_seed(POINT_MUL_BASE_SWEEP_SEED ^ 0x5AFEu);
        sweep_random_num(&k);

        pipeline_secp256k1_reset_op_count();
        pipeline_secp256k1_point_mul_base(&k, &fastPoint);
        pointFastOps = pipeline_secp256k1_get_op_count();

        pipeline_secp256k1_reset_op_count();
        pipeline_secp256k1_point_mul_base_reference(&k, &referencePoint);
        pointRefOps = pipeline_secp256k1_get_op_count();

        check(pointFastOps > 0 && pointRefOps > 0,
              "op-count proxy: both point_mul_base paths (comb table and the retained naive "
              "double-and-add reference) perform a nonzero number of counted operations");
        /* Measured ~80,084 (comb) vs ~253,562 (naive reference) for this
         * seed -- a ~3.2x drop, consistent with the theoretical ratio (up
         * to 512 Jacobian point operations for the naive 256-bit double-
         * and-add versus at most 86 -- COMB_E doublings + COMB_E additions,
         * 43 + 43 -- for the comb path, see secp256k1_baked.h's own header
         * comment). Asserted at 2x rather than the full measured ~3.2x for
         * margin against a different seed/scalar landing on a slightly
         * different exact ratio (the comb path's column-skip-on-zero-digit
         * case makes the exact op count scalar-dependent, unlike the field/
         * scalar sweeps' fixed-shape comparisons above). */
        check(pointFastOps * 2 < pointRefOps,
              "op-count proxy: the fixed-base comb table's k*G operation count is more than 2x "
              "lower than the retained naive double-and-add reference's, for the same full-width "
              "scalar (measured ~3.2x in practice) -- sub-issue #47's own acceptance criterion "
              "(\"the host op-count proxy shows the k*G cost dropping\"), independent of the "
              "whole-signature bound above");
        check(memcmp(&fastPoint.x, &referencePoint.x, sizeof(fastPoint.x)) == 0 &&
              memcmp(&fastPoint.y, &referencePoint.y, sizeof(fastPoint.y)) == 0 &&
              fastPoint.infinity == referencePoint.infinity,
              "op-count proxy: the comb and reference point_mul_base calls measured above also "
              "agree on the resulting point (correctness alongside cost, for this exact scalar)");
    }

    /*
     * (7) continued: fe_inv's own isolated fast-vs-naive comparison,
     * exactly mirroring (1)/(3)/(6) above -- pipeline_secp256k1_fe_inv_fast
     * (the addition chain) against the RETAINED naive reference
     * pipeline_secp256k1_fe_inv_reference (the exact fe_pow(a, p-2) Fermat
     * exponentiation fe_inv itself used before this sub-issue), for the
     * SAME field element, isolated from the rest of signing entirely.
     */
    {
        pipeline_secp256k1_num invA, invFast, invRef;
        unsigned long long invFastOps, invRefOps;

        sweep_rng_seed(FIELD_INV_SWEEP_SEED ^ 0xABCD1234u);
        field_test_random_nonzero_field_element(&invA);

        pipeline_secp256k1_reset_op_count();
        pipeline_secp256k1_fe_inv_fast(&invA, &invFast);
        invFastOps = pipeline_secp256k1_get_op_count();

        pipeline_secp256k1_reset_op_count();
        pipeline_secp256k1_fe_inv_reference(&invA, &invRef);
        invRefOps = pipeline_secp256k1_get_op_count();

        check(invFastOps > 0 && invRefOps > 0,
              "op-count proxy: both field-inversion paths perform a nonzero number of counted operations");
        /* fe_pow(a, p-2)'s square-and-multiply touches ~256 squarings plus
         * ~256 multiplies (p-2's bit pattern is essentially all ones) --
         * roughly double the fast chain's 255 squarings + 15 multiplications
         * (270 fe_mul calls total). Asserted at a conservative 1.5x rather
         * than the ~1.9x this ratio implies, for margin against fe_mul's
         * internal op count varying slightly with the specific operands. */
        check(invFastOps * 3 < invRefOps * 2,
              "op-count proxy: the fast addition-chain field inversion's operation count is more "
              "than 1.5x lower than the retained naive Fermat-exponentiation reference's, for the "
              "same operand -- sub-issue #48's own acceptance criterion (\"the host op-count proxy "
              "shows inversion cost dropping\"), independent of the whole-signature bound above");
        check(memcmp(&invFast, &invRef, sizeof(invFast)) == 0,
              "op-count proxy: the fast and reference field-inversion calls measured above also "
              "agree on the result (correctness alongside cost, for this exact operand)");
    }
}

/*
 * Live wire-vector regression (spec #52 / PR #56). The vectors in
 * fixtures/live_vectors.h are REAL format-v2 QR payloads captured off a
 * device screen (generated, sig-verified, and frozen by
 * fixtures/gen_live_vectors.mjs) -- not synthesized in this tool.
 *
 * Format v3 (spec #109, sub-issue #110) bumps FORMAT_TAG to 0x03 and
 * pipeline_unpack() now rejects anything else, INCLUDING these frozen v2
 * captures (0x02) -- exactly sub-issue #110's own explicit acceptance
 * criterion ("a 0x02 payload is rejected"). These vectors can no longer be
 * decode-and-broadcast round-tripped (their FORMAT_TAG byte is permanently
 * 0x02), so this regression now pins the OTHER half of the same real-device
 * story: that a genuine on-device v2 payload is cleanly and structurally
 * rejected by the v3 decoder, never silently misread. When format v3 ships
 * its own live captures, a companion "accepted" fixture set should replace
 * this one; until then, this is still real on-device bytes, still a real
 * regression guard, just pinning rejection instead of acceptance.
 */
static void test_live_wire_vectors_round_trip(void)
{
    unsigned int v;
    for (v = 0; v < PIPELINE_LIVE_VECTOR_COUNT; v++) {
        const PipelineLiveVector *vec = &k_pipeline_live_vectors[v];
        StarCapture capture;
        pipeline_u32 createdAt;
        pipeline_u8 pubkey[PIPELINE_FMT_SIZE_PUBKEY];
        pipeline_u8 tag[PIPELINE_PACK_MAX_TAG_LEN];
        pipeline_u8 tagLen;
        pipeline_u8 name[PIPELINE_PACK_MAX_NAME_LEN];
        pipeline_u8 nameLen;
        pipeline_u8 sig[PIPELINE_FMT_SIZE_SIG];
        int rc;

        rc = pipeline_unpack(vec->wire, vec->wire_len, &capture, &createdAt,
                             pubkey, tag, &tagLen, name, &nameLen, sig);
        check(rc == PIPELINE_UNPACK_ERR_BAD_FORMAT_TAG,
              "live vector: pipeline_unpack rejects the real on-device format-v2 wire bytes "
              "(FORMAT_TAG 0x02) under the v3-only decoder -- never silently misread as v3");
    }
}

int main(void)
{
    test_format_descriptor_round_trip();
    test_pubkey_known_answer();
    test_qr_round_trip_representative_sizes();
    test_qr_rejects_over_budget_cleanly();
    test_qr_alphanumeric_round_trip_and_rejections();
    test_base32_known_answer_vectors();
    test_fragment_boundaries_and_header_round_trip();
    test_url_wrap_and_strip();
    test_build_event_multiframe_round_trip();
    test_sha256_known_answer_vectors();
    test_event_id_matches_reference();
    test_event_name_change_changes_id();
    test_content_escaping_path();
    test_schnorr_signing_known_answer();
    test_schnorr_verify_internal_self_consistency();
    test_schnorr_sign_is_deterministic();
    test_baked_public_point_matches_reference();
    test_odd_y_parity_negation_branch();
    test_build_event_end_to_end();
    test_pipeline_unpack_boundary_and_rejections();
    test_pipeline_pack_unpack_name_round_trip();
    test_live_wire_vectors_round_trip();
    test_capture_build_known_answer();
    test_select_frames_real_course_elapsed();
    test_select_frames_real_course_at_entry_is_zero();
    test_select_frames_non_course_sentinel();
    test_select_frames_mips_star_index_elapsed();
    test_select_frames_non_mips_course_less_star_index_still_sentinel();
    test_capture_matches_host_build_event();
    test_qr_render_ascii_encoding();
    test_qr_render_layout_geometry();
    test_qr_render_blit_round_trips_through_decode();
    test_qr_render_overlay_paint();
    test_qr_render_glyph_orientation();
    test_qr_display_state_machine();
    test_field_mul_differential_sweep();
    test_field_inv_differential_sweep();
    test_scalar_differential_sweep();
    test_point_mul_base_comb_differential_sweep();
    test_field_op_count_proxy();

    if (g_failures != 0) {
        printf("%d check(s) FAILED\n", g_failures);
        return 1;
    }

    printf("All pipeline host tests PASSED\n");
    return 0;
}
