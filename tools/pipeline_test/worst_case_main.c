/*
 * Worst-case tag+name compile+build lock (spec #115, sub-issue #117): a
 * SEPARATE tiny host binary, built against its OWN generated event_profile.h
 * baked with format v3's actual worst-case field widths -- TAG_LEN=10 (the
 * per-game tag's own max, format_descriptor.json's TAG.max_size) and
 * NAME_LEN=15 (EVENT_NAME_MAX_LEN, the HUD glyph budget) -- rather than the
 * small "sm64"/"TEST" fixture pipeline_test's own main.c bakes (see this
 * directory's own Makefile comment on why that fixture stays small: a
 * readability choice, not a ceiling-driven one, now that ADR-0006's
 * multi-frame transport has retired the v2-era combined single-QR-frame
 * total-payload ceiling).
 *
 * This is a SEPARATE binary, not folded into main.c's own test suite,
 * because PIPELINE_BUILT_PAYLOAD_SIZE/PIPELINE_BUILT_FRAME_COUNT/etc. are
 * fixed COMPILE-TIME constants for a whole binary, derived from the ONE
 * event_profile.h linked into it (see build_event.h's own comment on this)
 * -- a single process can't exercise two different baked tag/name lengths
 * against build_event() at once. Before spec #115 sub-issue #117 removed
 * build_event.c's pipeline_build_event_payload_fits_qr_check compile-time
 * assert, THIS worst-case combination (113 B fixed spine + 10 B tag + 15 B
 * name = 138 B) failed to compile at all, with a cryptic "size of array
 * ... is negative" error -- exactly the failure mode spec #115's parent
 * issue (#115) and sub-issue #117 describe. This binary existing AND
 * compiling AND running successfully is itself the regression lock: a
 * reintroduced total-payload ceiling assert would break this build again,
 * loudly, at compile time.
 */

#include <stdio.h>
#include "build_event.h"

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

int main(void)
{
    /* BIP-340 test vector 0's private key (privkey=3) -- the same fixed,
     * published, never-real KAT key pipeline_test's own main.c uses
     * (TEST_PRIVKEY_HEX in this directory's Makefile); never the real
     * per-event secret. */
    static const pipeline_u8 kPrivkey[PIPELINE_KEY_SIZE] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3
    };
    StarCapture capture;
    BuiltEvent event;
    int buildOk;

    capture.course  = 8;
    capture.act     = 4;
    capture.coins   = 50;
    capture.frames  = 0x0BAD0BADu;
    capture.nonce16 = 0xABCD;
    capture.keyId   = 1;

    /* The acceptance criterion itself: format v3's own worst-case packed
     * payload (TAG_LEN=10, NAME_LEN=15, 138 B) is exactly
     * PIPELINE_FMT_FIXED_SIZE (113) + 10 + 15. Asserted here (a runtime
     * check, not a second compile-time typedef trick) purely so a future
     * drift in this fixture's own baked --tag/--event-name lengths (this
     * Makefile's WORSTCASE_TAG/WORSTCASE_EVENT_NAME) surfaces as a named,
     * readable failure rather than a silently-smaller-than-intended proof. */
    check(PIPELINE_BUILT_PAYLOAD_SIZE == 138u,
          "worst-case fixture's packed_payload size is exactly 138 B (113 fixed spine + 10-byte tag + 15-byte name)");

    buildOk = build_event(&capture, kPrivkey, &event);
    check(buildOk != 0,
          "build_event compiles AND succeeds for format v3's worst-case tag+name lengths "
          "(this is the exact combination that used to fail the ROM build at compile time "
          "with 'size of array ... is negative', per spec #115 sub-issue #117)");
    if (!buildOk) {
        /* Don't read event.frame_count below: on failure build_event() makes
         * no promise about out's contents (see build_event.h's own return-
         * value contract), so event is not guaranteed initialized here. */
        printf("%d worst-case check(s) FAILED\n", g_failures);
        return 1;
    }

    check(event.frame_count >= 2u,
          "worst-case build's 138 B payload, once base32-encoded/URL-wrapped, genuinely overflows a single "
          "QR frame (frame_count > 1) -- the multi-frame path is actually exercised, not accidentally N=1");

    if (g_failures != 0) {
        printf("%d worst-case check(s) FAILED\n", g_failures);
        return 1;
    }
    printf("All worst-case tag+name checks PASSED\n");
    return 0;
}
