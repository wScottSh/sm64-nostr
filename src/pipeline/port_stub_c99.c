/*
 * Stand-in for the eventual C99 internal ports (SHA-256, secp256k1 Schnorr,
 * qrcodegen -- see spec #24, sub-issue #25). The real ports are C99; this
 * stub exists purely to prove that one genuinely-C99 translation unit
 * compiles into both the ROM build and the host tool, settling the C99
 * build-integration question ahead of the real ports landing.
 *
 * This file deliberately uses `_Bool`, a keyword that exists only from
 * C99 onward (no stdbool.h needed to use it), so it genuinely fails to
 * compile under -std=gnu90 -- it cannot silently ride along with whatever
 * COMPILER is selected for the rest of the build. It must go through the
 * per-object C99 carve-out in the root Makefile (mirroring the existing
 * iQue per-object CC/CFLAGS override for IQUE_RECOMPILED).
 */

#include "port_stub_c99.h"

unsigned char port_stub_marker(void)
{
    _Bool ready = 1;
    unsigned char marker = 0;

    for (int i = 0; i < 1; i++) {
        if (ready) {
            marker = 0xA5;
        }
    }

    return marker;
}
