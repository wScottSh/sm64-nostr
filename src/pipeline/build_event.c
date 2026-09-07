/*
 * build_event -- pure pipeline stub (spec #24, sub-issue #25).
 *
 * Deliberately trivial: this sub-issue only proves the shared-source-
 * compiled-twice arrangement (ROM + host tool) and settles the C99
 * build-integration question via port_stub_c99.c. The real serialize ->
 * SHA-256 -> Schnorr sign -> pack -> QR encode chain is later sub-issues'
 * work.
 */

#include "build_event.h"
#include "port_stub_c99.h"

void build_event(const StarCapture *capture, const pipeline_u8 key[PIPELINE_KEY_SIZE], BuiltEvent *out)
{
    out->payload[0] = capture->course;
    out->payload[1] = capture->act;
    out->payload[2] = capture->coins;
    out->payload[3] = (pipeline_u8)(port_stub_marker() ^ key[0]);
}
