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
 * #32 adds test_qr_render_blit_round_trips_through_decode() (renderer
 * glue, src/game/qr_render.h/.c): renders a real build_event() qr_bitmap
 * into an in-memory plain RGBA16 buffer via the SAME pure
 * qr_render_blit_rgba16() the ROM build compiles (src/game is compiled a
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
 * build_event() end-to-end host test (spec #24, sub-issue #30).
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
 * kBuildEventExpectedSig is the BIP-340 signature of that exact id
 * (0x9d8360e4...58a7) under privkey 3 / aux_rand 0, independently computed
 * via @noble/curves (the same genuinely-separate library
 * tools/verify_schnorr_reference.js uses) -- NOT re-derived from this
 * repo's own pipeline_schnorr_sign(). This is the "independent verifier
 * convention already in the repo" this sub-issue's task calls for, applied
 * to a dynamic (non-all-zero-message) signature instead of BIP-340's own
 * canned test vector 0.
 */
static const pipeline_u8 kBuildEventPrivkey[PIPELINE_KEY_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
};
static const pipeline_u8 kBuildEventExpectedIdA[PIPELINE_EVENT_ID_SIZE] = {
    0xba, 0x23, 0x7b, 0x9e, 0x89, 0x1e, 0xde, 0x42, 0x12, 0x57, 0x1d, 0xed, 0x17, 0xbc, 0xe2, 0xa6,
    0x16, 0x19, 0x1e, 0xc6, 0x7a, 0x76, 0x32, 0xd2, 0x8d, 0xc9, 0xc5, 0x47, 0xd3, 0x54, 0x83, 0xcc,
};
static const pipeline_u8 kBuildEventExpectedSig[PIPELINE_SCHNORR_SIG_SIZE] = {
    0x60, 0x8b, 0x0f, 0xb8, 0x99, 0x4c, 0x16, 0x7a, 0x91, 0xc9, 0x9e, 0x1e, 0xcc, 0x0b, 0xb4, 0x7e,
    0x3b, 0xa6, 0xb1, 0x0c, 0x30, 0x5d, 0xac, 0x23, 0x5a, 0x06, 0x02, 0xff, 0x2b, 0x64, 0xc1, 0x0f,
    0xf3, 0xcf, 0x87, 0x98, 0x9d, 0xad, 0xd2, 0xfc, 0xa0, 0xce, 0x67, 0x8d, 0xfa, 0x19, 0xfc, 0xbf,
    0x35, 0x00, 0x4a, 0x77, 0x93, 0x98, 0xbc, 0x5b, 0x16, 0xea, 0xb7, 0x5c, 0x15, 0x02, 0x06, 0x7e,
};

static void test_build_event_end_to_end(void)
{
    StarCapture capture;
    BuiltEvent event;
    int buildOk;
    unsigned char decoded[PIPELINE_BUILT_PAYLOAD_SIZE];
    int decodedLen = -1;
    int decodeOk;
    StarCapture rebuilt;
    pipeline_u8 sigOut[PIPELINE_FMT_SIZE_SIG];
    int unpackRc;
    pipeline_u8 recomputedId[PIPELINE_EVENT_ID_SIZE];
    static const pipeline_u8 pubkey[32] = PIPELINE_EVENT_PUBKEY_BYTES;
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

    /* Report the actual packed payload size against the ~88 B spine (spec
     * #24): the literal 75 pins the current format_descriptor.json shape,
     * the same value test_format_descriptor_round_trip() already pins. */
    check(PIPELINE_BUILT_PAYLOAD_SIZE == 75u,
          "build_event's packed_payload size is 75 B, within the ~88 B spine budget");

    /* (a) the host decodes qr_bitmap back to the exact packed_payload. */
    decodeOk = qr_host_decode(event.qr_bitmap, decoded, (int)sizeof(decoded), &decodedLen);
    check(decodeOk != 0 && decodedLen == (int)PIPELINE_BUILT_PAYLOAD_SIZE &&
          memcmp(decoded, event.packed_payload, (size_t)PIPELINE_BUILT_PAYLOAD_SIZE) == 0,
          "qr_bitmap decodes back to the exact packed_payload byte-for-byte");

    /* (b) the host unpack+verify adapter (format-descriptor-derived)
     * rebuilds the event, recomputes the id, and verifies the signature. */
    unpackRc = pipeline_unpack(event.packed_payload, &rebuilt, sigOut);
    check(unpackRc == 0, "host pipeline_unpack accepts build_event's packed_payload");
    check(rebuilt.course == capture.course && rebuilt.act == capture.act &&
          rebuilt.coins == capture.coins && rebuilt.frames == capture.frames &&
          rebuilt.nonce16 == capture.nonce16 && rebuilt.keyId == capture.keyId,
          "unpacked StarCapture fields match the original capture exactly");

    pipeline_event_compute_id(&rebuilt, recomputedId);
    check(memcmp(recomputedId, kBuildEventExpectedIdA, PIPELINE_EVENT_ID_SIZE) == 0,
          "recomputed id from the rebuilt event matches the nostr-tools reference id (vector A)");

    check(memcmp(sigOut, kBuildEventExpectedSig, PIPELINE_SCHNORR_SIG_SIZE) == 0,
          "build_event's signature matches the independently-computed BIP-340 signature (@noble/curves oracle)");

    verifyOk = pipeline_schnorr_verify(recomputedId, pubkey, sigOut);
    check(verifyOk != 0,
          "signature verifies against the recomputed id and the build's pubkey (rebuild-id+verify-accept)");

    /* (c) a single flipped payload byte fails verification. Flip a content
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
     * doesn't identify which star was grabbed. It does NOT hold for
     * FORMAT_TAG, which pipeline_unpack() checks structurally (see the second
     * check below), not cryptographically. */
    {
        pipeline_u8 corrupted[PIPELINE_BUILT_PAYLOAD_SIZE];
        StarCapture corruptCapture;
        pipeline_u8 corruptSig[PIPELINE_FMT_SIZE_SIG];
        pipeline_u8 corruptId[PIPELINE_EVENT_ID_SIZE];
        int corruptVerify;
        int corruptUnpackRc;

        memcpy(corrupted, event.packed_payload, (size_t)PIPELINE_BUILT_PAYLOAD_SIZE);
        corrupted[PIPELINE_FMT_OFF_COURSE] ^= 0x01;

        pipeline_unpack(corrupted, &corruptCapture, corruptSig);
        pipeline_event_compute_id(&corruptCapture, corruptId);
        corruptVerify = pipeline_schnorr_verify(corruptId, pubkey, corruptSig);
        check(corruptVerify == 0,
              "flipping one packed_payload byte (a signed content field) makes signature verification fail");

        /* A flipped FORMAT_TAG byte is rejected structurally, before
         * verification is even attempted -- a different, but equally
         * real, tamper-evidence path. */
        memcpy(corrupted, event.packed_payload, (size_t)PIPELINE_BUILT_PAYLOAD_SIZE);
        corrupted[PIPELINE_FMT_OFF_FORMAT_TAG] ^= 0x01;
        corruptUnpackRc = pipeline_unpack(corrupted, &corruptCapture, corruptSig);
        check(corruptUnpackRc != 0,
              "flipping the FORMAT_TAG byte is rejected structurally by pipeline_unpack");

        /* A flipped KEY_ID byte (the star index) must also fail verification:
         * keyId is signed content, so tampering with which star was grabbed
         * breaks the signature -- the regression guard for the tamper hole
         * closed by adding keyId to pipeline_event_build_content(). */
        memcpy(corrupted, event.packed_payload, (size_t)PIPELINE_BUILT_PAYLOAD_SIZE);
        corrupted[PIPELINE_FMT_OFF_KEY_ID] ^= 0x01;
        pipeline_unpack(corrupted, &corruptCapture, corruptSig);
        pipeline_event_compute_id(&corruptCapture, corruptId);
        corruptVerify = pipeline_schnorr_verify(corruptId, pubkey, corruptSig);
        check(corruptVerify == 0,
              "flipping the KEY_ID byte (signed star index) makes signature verification fail");
    }
}

#define QR_RENDER_TEST_FB_WIDTH  320
#define QR_RENDER_TEST_FB_HEIGHT 240

/*
 * qr_render_blit_rgba16() round-trip test (spec #24, sub-issue #32). See
 * the file header comment above for the full render->reconstruct->decode
 * shape. Uses a StarCapture distinct from vector A above just to exercise
 * a different payload, signed with the same BIP-340 KAT privkey.
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
    unsigned char decoded[PIPELINE_BUILT_PAYLOAD_SIZE];
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
     * the blit -- qr_render_blit_rgba16() itself now refuses to write
     * anything if this doesn't hold (see qr_render.c's own defensive
     * bound), but this test's own geometry assertions must not run after
     * a call that could, in principle, already have misbehaved. */
    gridSize  = pipeline_qr_get_size(event.qr_bitmap);
    imageSize = (gridSize + 2 * QR_RENDER_QUIET_ZONE_MODULES) * QR_RENDER_MODULE_SCALE_PX;
    originX = (QR_RENDER_TEST_FB_WIDTH  - imageSize) / 2;
    originY = (QR_RENDER_TEST_FB_HEIGHT - imageSize) / 2;

    check(imageSize == QR_RENDER_IMAGE_SIZE_PX,
          "qr_render: computed image size matches QR_RENDER_IMAGE_SIZE_PX (196x196 for v6/scale4/quiet4)");
    check(imageSize <= QR_RENDER_TEST_FB_WIDTH && imageSize <= QR_RENDER_TEST_FB_HEIGHT,
          "qr_render: image fits within the 320x240 N64 framebuffer");
    if (imageSize > QR_RENDER_TEST_FB_WIDTH || imageSize > QR_RENDER_TEST_FB_HEIGHT) {
        return;
    }

    qr_render_blit_rgba16(event.qr_bitmap, fb, QR_RENDER_TEST_FB_WIDTH, QR_RENDER_TEST_FB_HEIGHT);

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
            int isDark = pipeline_qr_get_module(event.qr_bitmap, col, row);
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

    decodeOk = qr_host_decode(reconstructed, decoded, (int) sizeof(decoded), &decodedLen);
    check(decodeOk != 0 && decodedLen == (int) PIPELINE_BUILT_PAYLOAD_SIZE &&
          memcmp(decoded, event.packed_payload, (size_t) PIPELINE_BUILT_PAYLOAD_SIZE) == 0,
          "qr_render: render->reconstruct->decode == build_event's exact packed_payload");
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
    pipeline_u8 packed[PIPELINE_PACKED_SIZE];
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

    memset(packed, 0xFF, sizeof(packed));
    pipeline_pack(&capture, sig, packed);

    check(packed[0] == PIPELINE_FMT_TAG_VALUE, "packed payload leads with the format tag");
    /* Literal 75, not PIPELINE_FMT_TOTAL_SIZE: this pins the descriptor's
     * own size accounting to an independently-computed value (1 + 1 + 1 +
     * 1 + 4 + 2 + 1 + 64), rather than comparing the macro to itself. */
    check(PIPELINE_FMT_TOTAL_SIZE == 75u,
          "format descriptor's total size matches the expected field layout");

    rc = pipeline_unpack(packed, &roundTripped, sigRoundTripped);
    check(rc == 0, "unpack accepts a correctly-tagged payload");
    check(roundTripped.course == capture.course &&
          roundTripped.act == capture.act &&
          roundTripped.coins == capture.coins &&
          roundTripped.frames == capture.frames &&
          roundTripped.nonce16 == capture.nonce16 &&
          roundTripped.keyId == capture.keyId,
          "unpack round-trips all StarCapture fields exactly");
    check(memcmp(sig, sigRoundTripped, PIPELINE_FMT_SIZE_SIG) == 0,
          "unpack round-trips the signature bytes exactly");

    /* Corrupt the format tag and confirm unpack rejects it. */
    packed[0] = (pipeline_u8)(PIPELINE_FMT_TAG_VALUE + 1);
    rc = pipeline_unpack(packed, &roundTripped, sigRoundTripped);
    check(rc != 0, "unpack rejects a payload with the wrong format tag");
}

/*
 * QR round-trip tests (spec #24, sub-issue #27). Exercises the internal
 * seam directly: pipeline_qr_encode() (qr_adapter.h, which hides the
 * ported qrcodegen.c behind it) followed by qr_host_decode() (host-only,
 * tools/pipeline_test/qr_host_decode.c -- never linked into the ROM). See
 * qr_adapter.h for the version 6 / ECC MEDIUM / 106-byte-usable-payload
 * (108 total data codewords, minus the mode+count header) choice.
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
    check_round_trip(75, "current format_descriptor.json total size");
    check_round_trip(88, "spec #24's ~88 B payload budget");
    check_round_trip(PIPELINE_QR_MAX_PAYLOAD_BYTES, "exact version 6 / ECC MEDIUM usable payload capacity (106 B)");
}

static void test_qr_rejects_over_budget_cleanly(void)
{
    pipeline_u8 payload[PIPELINE_QR_MAX_PAYLOAD_BYTES + 1];
    pipeline_u8 qrcode[PIPELINE_QR_BUFFER_LEN];
    int encodeOk;

    fill_pattern(payload, (int)sizeof(payload), 0x5A);

    /* One byte over the real version 6 / ECC MEDIUM capacity: must be
     * rejected cleanly (nonzero return, no truncated/partial QR Code
     * written -- qrcode[0] is left at the documented invalid-size
     * sentinel of 0), never silently truncated to fit. */
    memset(qrcode, 0xFF, sizeof(qrcode));
    encodeOk = pipeline_qr_encode(payload, (pipeline_u32)sizeof(payload), qrcode);
    check(encodeOk == 0, "QR encode rejects a payload one byte over the 106 B usable payload capacity");
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
     * faithful independent oracle. */
    static const pipeline_u8 kExpectedIdA[32] = {
        0xba, 0x23, 0x7b, 0x9e, 0x89, 0x1e, 0xde, 0x42, 0x12, 0x57, 0x1d, 0xed, 0x17, 0xbc, 0xe2, 0xa6,
        0x16, 0x19, 0x1e, 0xc6, 0x7a, 0x76, 0x32, 0xd2, 0x8d, 0xc9, 0xc5, 0x47, 0xd3, 0x54, 0x83, 0xcc,
    };
    static const pipeline_u8 kExpectedIdB[32] = {
        0x00, 0x92, 0xdc, 0x5f, 0xe5, 0xb5, 0x4a, 0x5e, 0x2c, 0x09, 0x66, 0x67, 0x27, 0xe8, 0xa3, 0xcf,
        0xce, 0x46, 0x42, 0x42, 0x99, 0x1b, 0xea, 0x6b, 0x1d, 0x71, 0xfd, 0x89, 0x75, 0x1d, 0x0e, 0x24,
    };
    static const pipeline_u8 kExpectedIdC[32] = {
        0xe9, 0xe1, 0x29, 0x92, 0x09, 0xba, 0x35, 0xde, 0xb9, 0x79, 0x1a, 0xad, 0xb3, 0x4c, 0x4d, 0x87,
        0xb7, 0x35, 0xa4, 0xe1, 0x77, 0x6f, 0x51, 0x61, 0x05, 0x41, 0xd6, 0x14, 0x34, 0xee, 0x18, 0xeb,
    };

    captureA.course = 15; captureA.act = 6; captureA.coins = 100; captureA.frames = 0x01020304u; captureA.nonce16 = 0xCAFE; captureA.keyId = 0;
    captureB.course = 9;  captureB.act = 1; captureB.coins = 42;  captureB.frames = 1234u;        captureB.nonce16 = 0xBEEF; captureB.keyId = 0;
    captureC.course = 0;  captureC.act = 0; captureC.coins = 0;   captureC.frames = 0u;            captureC.nonce16 = 0;      captureC.keyId = 0;

    check_event_id(&captureA, kExpectedIdA, "event id matches nostr-tools reference (vector A)");
    check_event_id(&captureB, kExpectedIdB, "event id matches nostr-tools reference (vector B)");
    check_event_id(&captureC, kExpectedIdC, "event id matches nostr-tools reference (all-zero vector C)");
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
     * tools/reference_event_id.js). Pinning the whole 219-byte buffer, not
     * just a substring, proves the prefix/field ordering/escaping directly
     * rather than only through the opaque id in the test above. */
    const char *expectedSerialized =
        "[0,\"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9\","
        "1700000000,8064,[[\"t\",\"cabinet-leaderboard\"],[\"t\",\"sm64\"]],"
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
            eventFromGlue.packed_payload[PIPELINE_FMT_OFF_FORMAT_TAG] == 1 &&
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
              && memcmp(eventFromGlue.qr_bitmap, eventFromHand.qr_bitmap,
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
        if (event.qr_bitmap[i] != 0) {
            anyNonZero = 1;
            break;
        }
    }
    check(anyNonZero, "qr_display: the built qr_bitmap under test is not already all-zero");

    qr_display_init(&state);
    check(!qr_display_is_active(&state), "qr_display: freshly-initialized state is not active");

    check(qr_display_present(&state, event.qr_bitmap) != 0,
          "qr_display: present() succeeds on a fresh state");
    check(qr_display_is_active(&state), "qr_display: state is active immediately after present()");
    check(memcmp(state.bitmap, event.qr_bitmap, PIPELINE_BUILT_QR_BITMAP_SIZE) == 0,
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
    check(qr_display_present(&state, event.qr_bitmap) == 0,
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

int main(void)
{
    test_format_descriptor_round_trip();
    test_pubkey_known_answer();
    test_qr_round_trip_representative_sizes();
    test_qr_rejects_over_budget_cleanly();
    test_sha256_known_answer_vectors();
    test_event_id_matches_reference();
    test_content_escaping_path();
    test_schnorr_signing_known_answer();
    test_schnorr_verify_internal_self_consistency();
    test_schnorr_sign_is_deterministic();
    test_baked_public_point_matches_reference();
    test_odd_y_parity_negation_branch();
    test_build_event_end_to_end();
    test_capture_build_known_answer();
    test_capture_matches_host_build_event();
    test_qr_render_blit_round_trips_through_decode();
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
