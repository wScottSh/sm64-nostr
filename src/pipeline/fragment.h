#ifndef PIPELINE_FRAGMENT_H
#define PIPELINE_FRAGMENT_H

/*
 * The fragmenter (ADR-0006's airgap transport, spec #115 sub-issue #116):
 * a pure, pipeline-internal seam splitting base32 text into indexed
 * fragments, each sized to one QR frame's alphanumeric budget. Like
 * base32.h/.c, this file is pure C89, compiled a second time, unmodified,
 * into the host test tool (tools/pipeline_test).
 *
 * Contract: pipeline_fragment_count() and pipeline_fragment_build() are a
 * pure function of (base32 text length, per-frame alnum budget) -> N
 * fragments, one at a time by index -- no array-of-strings return, no
 * malloc, matching this pipeline's caller-supplies-the-buffer convention
 * (pipeline_pack(), pipeline_qr_encode()). A payload whose base32 text fits
 * one frame's budget is the N=1 case (a single static QR); when it does
 * not, N>1 fragments are produced, each carrying a fragment header (its
 * own 0-based index and the total frame count, both in the QR alphanumeric
 * charset -- see transport_contract.h) ahead of its slice of the base32
 * text. Fragments reassemble in ANY order (each carries its own index);
 * pipeline_fragment_parse_header() is the read side of that same header,
 * used by this build's own host round-trip test and, independently
 * ported, by ticket #119's reader page.
 *
 * perFrameBudget here is the TOTAL per-fragment character budget (header +
 * chunk), not the QR's raw alphanumeric capacity -- the caller (build_event.c)
 * is responsible for first subtracting the fixed URL prefix
 * (PIPELINE_URL_SCHEME + the build's own PIPELINE_URL_BASE + the path
 * separator) from the QR's real alphanumeric budget, since every fragment
 * is wrapped in a complete URL before being QR-encoded (url.h).
 */

#include "build_event.h"
#include "transport_contract.h"

/*
 * pipeline_fragment_count: the number of fragments a base32Len-character
 * payload splits into at perFrameBudget characters (header + chunk) per
 * fragment. Returns 1 for an empty payload (base32Len == 0, the degenerate
 * N=1 case) and otherwise ceil(base32Len / (perFrameBudget -
 * PIPELINE_FRAGMENT_HEADER_LEN)). Returns 0 -- an invalid budget -- if
 * perFrameBudget leaves no room for at least one chunk byte
 * (perFrameBudget <= PIPELINE_FRAGMENT_HEADER_LEN) or if the payload would
 * need more than PIPELINE_FRAGMENT_MAX_COUNT fragments to carry (a two-
 * base36-digit index/count field cannot address that many).
 */
pipeline_u32 pipeline_fragment_count(pipeline_u32 base32Len, pipeline_u32 perFrameBudget);

/*
 * pipeline_fragment_build: writes fragment number frameIndex (0-based) of
 * frameCount total -- frameCount MUST equal pipeline_fragment_count(base32Len,
 * perFrameBudget), a caller contract this function does not re-derive --
 * into out, as PIPELINE_FRAGMENT_HEADER_LEN header bytes (frameIndex then
 * frameCount, each base36, uppercase) followed by this fragment's slice of
 * base32Text[0 : base32Len] (frameIndex * chunkLen .. capped at base32Len).
 * out must be at least perFrameBudget bytes. Writes *outLen (<=
 * perFrameBudget) on success and returns nonzero (true). Returns 0
 * (false) -- writing nothing -- if perFrameBudget/frameCount/frameIndex
 * are not self-consistent (perFrameBudget too small for even the header,
 * frameCount == 0 or over PIPELINE_FRAGMENT_MAX_COUNT, or frameIndex >=
 * frameCount).
 */
int pipeline_fragment_build(const pipeline_u8 *base32Text, pipeline_u32 base32Len,
                             pipeline_u32 perFrameBudget, pipeline_u32 frameIndex,
                             pipeline_u32 frameCount, pipeline_u8 *out, pipeline_u32 *outLen);

/*
 * pipeline_fragment_parse_header: reads fragment[0 : PIPELINE_FRAGMENT_HEADER_LEN]
 * (the header pipeline_fragment_build() wrote) back into *frameIndexOut/
 * *frameCountOut. Returns nonzero (true) on success. Returns 0 (false) --
 * writing nothing -- if fragmentLen is shorter than the header, either
 * field contains a non-base36 byte, the decoded count is 0, or the decoded
 * index is >= the decoded count (a structurally invalid header). The
 * fragment's chunk bytes are fragment[PIPELINE_FRAGMENT_HEADER_LEN :
 * fragmentLen]; this function does not copy them out, since a caller
 * already holds fragment[] and can slice it directly.
 */
int pipeline_fragment_parse_header(const pipeline_u8 *fragment, pipeline_u32 fragmentLen,
                                    pipeline_u32 *frameIndexOut, pipeline_u32 *frameCountOut);

#endif /* PIPELINE_FRAGMENT_H */
