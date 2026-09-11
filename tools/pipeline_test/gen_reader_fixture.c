/*
 * gen_reader_fixture -- dumps a KNOWN build_event() call's real emitted
 * frames (spec #115, sub-issue #119) to a JSON fixture the reader page's
 * (reader/) host-side tests decode/reassemble/id-recompute against.
 *
 * NOT part of any ROM build path (mirrors the same host-only conventions
 * already established by tools/reference_event_id.js and
 * tools/pipeline_test/fixtures/gen_live_vectors.mjs). Links the SAME pure
 * pipeline sources as pipeline_test (this Makefile's own $(SRCS)) against
 * the SAME generated event_profile.h/format_descriptor.h (privkey=3 KAT,
 * tag "sm64", event name "TEST", url-base SM64NOSTR.PAGES.DEV) that
 * main.c's test_build_event_end_to_end() already pins kBuildEventExpectedIdA/
 * kBuildEventExpectedSig against -- so this fixture's own StarCapture
 * (vector A: course=15, act=6, coins=100, frames=0x01020304, nonce16=0xCAFE,
 * keyId=0) reuses those same independently-oracled values.
 *
 * Every frame's URL text is recovered via qr_host_decode_mixed() (spec
 * #122, sub-issue #123 -- #101's ratified <BASE>#<SEQ>/<TOTAL>/<PAYLOAD>
 * template rides a two-segment QR: a BYTE segment for the verbatim
 * <BASE># prefix, an ALPHANUMERIC segment for the fragment tail) -- the
 * SAME structural QR bitmap decoder main.c's own reassemble_built_event()
 * uses -- so the fixture's "frames" array is the real per-frame QR content,
 * not a hand-derived string. Before writing anything, this program
 * independently re-derives the expected id (event_id.h's generic
 * pipeline_event_compute_id_from_fields(), fed the UNPACKED wire fields --
 * never event_profile.h's baked macros) and verifies the unpacked signature
 * against it (pipeline_schnorr_verify()) -- both are the exact operations
 * the reader page's zero-far-side-reconstruction contract permits, run here
 * as a self-check so a broken fixture can never be committed (mirrors
 * gen_live_vectors.mjs's own sig_ok abort-on-failure discipline).
 *
 * Usage: ./gen_reader_fixture > ../../reader/test/fixtures/multiframe_fixture.json
 */
#include <stdio.h>
#include <string.h>

#include "build_event.h"
#include "pack_adapter.h"
#include "event_profile.h"
#include "qr_adapter.h"
#include "qr_host_decode.h"
#include "event_id.h"
#include "schnorr_adapter.h"

static void print_hex(const pipeline_u8 *bytes, pipeline_u32 len)
{
    pipeline_u32 i;
    for (i = 0; i < len; i++) {
        printf("%02x", bytes[i]);
    }
}

static void print_json_string(const char *s, pipeline_u32 len)
{
    pipeline_u32 i;
    putchar('"');
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') {
            putchar('\\');
        }
        putchar((int)c);
    }
    putchar('"');
}

int main(void)
{
    StarCapture capture;
    BuiltEvent event;
    static const pipeline_u8 privkey[PIPELINE_KEY_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
    };
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
    int verifyOk;
    pipeline_u32 i;
    static const pipeline_u8 kUrlBase[] = PIPELINE_URL_BASE;

    capture.course  = 15;
    capture.act     = 6;
    capture.coins   = 100;
    capture.frames  = 0x01020304u;
    capture.nonce16 = 0xCAFE;
    capture.keyId   = 0;

    if (!build_event(&capture, privkey, &event)) {
        fprintf(stderr, "build_event failed\n");
        return 1;
    }

    unpackRc = pipeline_unpack(event.packed_payload, (pipeline_u32)PIPELINE_BUILT_PAYLOAD_SIZE,
                               &rebuilt, &createdAtOut, pubkeyOut,
                               tagOut, &tagLenOut, nameOut, &nameLenOut, sigOut);
    if (unpackRc != PIPELINE_UNPACK_OK) {
        fprintf(stderr, "pipeline_unpack failed: %d\n", unpackRc);
        return 1;
    }

    /* Self-check (never emit a fixture whose id/sig don't verify): recompute
     * the id purely from UNPACKED wire fields -- zero out-of-band constants,
     * exactly the operation the reader page itself is permitted to perform --
     * and verify the unpacked signature against it. */
    pipeline_event_compute_id_from_fields(pubkeyOut, createdAtOut, (const char *)tagOut, tagLenOut,
                                           (const char *)nameOut, nameLenOut, &rebuilt, recomputedId);
    verifyOk = pipeline_schnorr_verify(recomputedId, pubkeyOut, sigOut);
    if (!verifyOk) {
        fprintf(stderr, "self-check FAILED: recomputed id's signature does not verify -- refusing to "
                        "write a bad fixture\n");
        return 1;
    }

    printf("{\n");
    printf("  \"_comment\": \"GENERATED by tools/pipeline_test/gen_reader_fixture.c -- DO NOT EDIT. "
           "A real build_event() call's actual emitted QR frames (full <BASE>#<SEQ>/<TOTAL>/<PAYLOAD> "
           "URL text per spec #122's ratified template, recovered via the same structural "
           "qr_host_decode_mixed() main.c's own round-trip test uses), for the reader page's "
           "(reader/) host-side reassembly/decode/id-recompute test (spec #115 sub-issue #119, "
           "realigned by spec #122 sub-issue #123). urlBase is informational only -- the reader's "
           "own reassembleFrames()/extractFragment() are host-agnostic and take no base-URL "
           "argument. Regenerate: cd tools/pipeline_test && make reader-fixture\",\n");
    printf("  \"urlBase\": ");
    print_json_string((const char *)kUrlBase, (pipeline_u32)PIPELINE_URL_BASE_LEN);
    printf(",\n");
    printf("  \"frameCount\": %u,\n", (unsigned)event.frame_count);
    printf("  \"frames\": [\n");
    for (i = 0; i < event.frame_count; i++) {
        unsigned char urlText[PIPELINE_BUILT_URL_MAX_LEN];
        int urlTextLen = -1;
        if (!qr_host_decode_mixed(event.qr_bitmaps[i], urlText, (int)sizeof(urlText), &urlTextLen)) {
            fprintf(stderr, "qr_host_decode_mixed failed for frame %u\n", (unsigned)i);
            return 1;
        }
        printf("    ");
        print_json_string((const char *)urlText, (pipeline_u32)urlTextLen);
        printf(i + 1 < event.frame_count ? ",\n" : "\n");
    }
    printf("  ],\n");
    printf("  \"packedPayloadHex\": \"");
    print_hex(event.packed_payload, (pipeline_u32)PIPELINE_BUILT_PAYLOAD_SIZE);
    printf("\",\n");
    printf("  \"capture\": { \"course\": %u, \"act\": %u, \"coins\": %u, \"frames\": %u, "
           "\"nonce16\": %u, \"keyId\": %u },\n",
           (unsigned)rebuilt.course, (unsigned)rebuilt.act, (unsigned)rebuilt.coins,
           (unsigned)rebuilt.frames, (unsigned)rebuilt.nonce16, (unsigned)rebuilt.keyId);
    printf("  \"createdAt\": %u,\n", (unsigned)createdAtOut);
    printf("  \"pubkeyHex\": \"");
    print_hex(pubkeyOut, (pipeline_u32)PIPELINE_FMT_SIZE_PUBKEY);
    printf("\",\n");
    printf("  \"tag\": ");
    print_json_string((const char *)tagOut, (pipeline_u32)tagLenOut);
    printf(",\n");
    printf("  \"name\": ");
    print_json_string((const char *)nameOut, (pipeline_u32)nameLenOut);
    printf(",\n");
    printf("  \"sigHex\": \"");
    print_hex(sigOut, (pipeline_u32)PIPELINE_FMT_SIZE_SIG);
    printf("\",\n");
    printf("  \"expectedIdHex\": \"");
    print_hex(recomputedId, (pipeline_u32)PIPELINE_EVENT_ID_SIZE);
    printf("\"\n");
    printf("}\n");

    return 0;
}
