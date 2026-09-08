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
 */
#include <stdio.h>
#include <string.h>

#include "build_event.h"
#include "pack_adapter.h"
#include "event_profile.h"
#include "qr_adapter.h"
#include "qr_host_decode.h"

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

int main(void)
{
    test_format_descriptor_round_trip();
    test_pubkey_known_answer();
    test_build_event_stub();
    test_qr_round_trip_representative_sizes();
    test_qr_rejects_over_budget_cleanly();

    if (g_failures != 0) {
        printf("%d check(s) FAILED\n", g_failures);
        return 1;
    }

    printf("All pipeline host tests PASSED\n");
    return 0;
}
