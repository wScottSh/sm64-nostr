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

static void test_build_event_stub(void)
{
    StarCapture capture;
    pipeline_u8 key[PIPELINE_KEY_SIZE];
    BuiltEvent event;
    pipeline_u8 expected[PIPELINE_STUB_PAYLOAD_SIZE];
    int i;

    capture.course  = 9;
    capture.act     = 1;
    capture.coins   = 42;
    capture.frames  = 1234;
    capture.nonce16 = 0xBEEF;
    capture.keyId   = 0;

    for (i = 0; i < PIPELINE_KEY_SIZE; i++) {
        key[i] = (pipeline_u8)i;
    }

    build_event(&capture, key, &event);

    expected[0] = capture.course;
    expected[1] = capture.act;
    expected[2] = capture.coins;
    expected[3] = (pipeline_u8)(0xA5 ^ key[0]); /* port_stub_marker() ^ key[0] */

    check(memcmp(event.payload, expected, PIPELINE_STUB_PAYLOAD_SIZE) == 0,
          "pipeline stub build_event byte-exact");
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
        0x9d, 0x83, 0x60, 0xe4, 0x0c, 0x2c, 0xbf, 0x09, 0xbb, 0xe5, 0x88, 0x73, 0x5c, 0xc7, 0xc4, 0xf7,
        0xe6, 0x11, 0x26, 0x01, 0x2c, 0x7a, 0x5d, 0x1a, 0x8e, 0xdc, 0x6f, 0xb5, 0x37, 0x07, 0x58, 0xa7,
    };
    static const pipeline_u8 kExpectedIdB[32] = {
        0xe5, 0xf9, 0xfb, 0x87, 0x1c, 0xfd, 0xa9, 0xb4, 0x6c, 0x76, 0x0c, 0x64, 0xd2, 0x17, 0x55, 0x07,
        0xe4, 0x99, 0xef, 0xa3, 0x4f, 0xed, 0xaa, 0x61, 0x2e, 0xc9, 0x54, 0x84, 0xc5, 0x7b, 0x96, 0x49,
    };
    static const pipeline_u8 kExpectedIdC[32] = {
        0xbe, 0x7d, 0xb6, 0x93, 0xf0, 0x2f, 0x58, 0xff, 0xbd, 0xa2, 0xfd, 0xc6, 0xec, 0x7c, 0xf8, 0x09,
        0xb5, 0x98, 0xd1, 0x1e, 0x91, 0x94, 0xbe, 0x15, 0xa9, 0xc6, 0x81, 0x12, 0xea, 0xcf, 0x98, 0x03,
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
    const char *expectedContent = "{\"course\":15,\"act\":6,\"coins\":100,\"frames\":16909060,\"nonce\":51966}";
    /* The FULL expected canonical serialization for this exact StarCapture
     * (vector A, same as test_event_id_matches_reference()'s captureA) and
     * the baked event profile (pubkey f9308a.../created_at 1700000000/kind
     * 8064/the two t tags) -- cross-checked byte-for-byte against
     * JSON.stringify([0,pubkey,created_at,kind,tags,content]) via Node, the
     * same expression nostr-tools' getEventHash() evaluates (see
     * tools/reference_event_id.js). Pinning the whole 207-byte buffer, not
     * just a substring, proves the prefix/field ordering/escaping directly
     * rather than only through the opaque id in the test above. */
    const char *expectedSerialized =
        "[0,\"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9\","
        "1700000000,8064,[[\"t\",\"cabinet-leaderboard\"],[\"t\",\"sm64\"]],"
        "\"{\\\"course\\\":15,\\\"act\\\":6,\\\"coins\\\":100,\\\"frames\\\":16909060,\\\"nonce\\\":51966}\"]";

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

int main(void)
{
    test_format_descriptor_round_trip();
    test_pubkey_known_answer();
    test_build_event_stub();
    test_qr_round_trip_representative_sizes();
    test_qr_rejects_over_budget_cleanly();
    test_sha256_known_answer_vectors();
    test_event_id_matches_reference();
    test_content_escaping_path();

    if (g_failures != 0) {
        printf("%d check(s) FAILED\n", g_failures);
        return 1;
    }

    printf("All pipeline host tests PASSED\n");
    return 0;
}
