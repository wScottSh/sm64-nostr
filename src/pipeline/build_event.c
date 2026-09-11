/*
 * build_event -- the pipeline's real interface (spec #24, sub-issue #30;
 * format v2 self-contained payload, spec #52 sub-issue #54; format v3
 * signed event-name tag, spec #109 sub-issue #111).
 *
 * Wires the internal seams together, in order: canonical NIP-01 serialize +
 * SHA-256 id (event_id.h) -> BIP-340 Schnorr sign of that id
 * (schnorr_adapter.h) -> pack capture's fields + createdAt + pubkey + the
 * per-game tag + the event name + the signature into the wire payload
 * (pack_adapter.h) -> QR-encode that payload (qr_adapter.h).
 * createdAt/pubkey/the per-game tag/the event name are sourced from the
 * generated event_profile.h -- the SAME baked values event_id.c's
 * pipeline_event_serialize() already uses for the signed serialization, so
 * the packed wire bytes and the signed content can never disagree. See
 * build_event.h for the full interface contract.
 */

#include "build_event.h"
#include "event_id.h"
#include "schnorr_adapter.h"
#include "pack_adapter.h"
#include "qr_adapter.h"
#include "base32.h"
#include "fragment.h"
#include "url.h"

/* Compile-time checks that build_event.h's own duplicated size/version
 * constants (kept there instead of #including pack_adapter.h/qr_adapter.h --
 * the former to avoid a genuine circular include, the latter to avoid
 * leaking qrcodegen.h's public surface into every build_event.h consumer;
 * see build_event.h's own comments on both) still agree with the values
 * pipeline_pack()/pipeline_qr_encode() below actually use. If
 * qr_adapter.h's fixed QR version ever changes without updating
 * build_event.h to match, these fail to compile (negative array size)
 * instead of silently sizing BuiltEvent wrong.
 *
 * This build's own tag-length guard (spec #52, sub-issue #54): a per-game
 * tag baked via gen_event_profile.py's --tag must itself stay within
 * pack_adapter.h's PIPELINE_PACK_MAX_TAG_LEN (10 B, v7-MEDIUM's budget) --
 * pipeline_pack()'s own runtime check (returning 0) already catches this at
 * build_event() call time (see the packedLen check below), but failing at
 * COMPILE time, not just "the ROM silently never grabs a star", is the
 * loud-not-silent failure this pipeline's own conventions call for. The
 * same discipline applies to the baked event name (spec #109, sub-issue
 * #111; cap raised 15->20, spec #91 sub-issue #126): gen_event_profile.py's
 * own EVENT_NAME_MAX_LEN cap (20) already keeps PIPELINE_EVENT_NAME_LEN
 * within PIPELINE_PACK_MAX_NAME_LEN, but this compile-time check catches a
 * future drift between the two loud, not silent. Both caps are
 * independent, per-field budgets of the WIRE pack
 * format itself (format_descriptor.json's own TAG/NAME max_size, PIPELINE_
 * PACK_MAX_TAG_LEN/PIPELINE_PACK_MAX_NAME_LEN) -- as of ADR-0006's
 * multi-frame transport (spec #115, sub-issue #117), neither also has to
 * fit some COMBINED single-QR-frame total-payload ceiling: a tag+name
 * combination that used to overflow one frame now simply produces more
 * frames (see the base32/fragment/URL section below), never a compile
 * error. */
typedef char pipeline_build_event_tag_len_check[
    (PIPELINE_EVENT_TAG_1_LEN <= PIPELINE_PACK_MAX_TAG_LEN) ? 1 : -1];
typedef char pipeline_build_event_name_len_check[
    (PIPELINE_EVENT_NAME_LEN <= PIPELINE_PACK_MAX_NAME_LEN) ? 1 : -1];
typedef char pipeline_build_event_qr_version_check[
    (PIPELINE_BUILT_QR_VERSION == PIPELINE_QR_VERSION) ? 1 : -1];
typedef char pipeline_build_event_qr_bitmap_size_check[
    (PIPELINE_BUILT_QR_BITMAP_SIZE == PIPELINE_QR_BUFFER_LEN) ? 1 : -1];

/*
 * ADR-0006 multi-frame transport checks (spec #115, sub-issue #116),
 * mirroring the discipline of the five checks above: build_event.h
 * duplicates a handful of qr_adapter.h/base32.h formulas/constants rather
 * than #including those headers (circular-include hazard -- see
 * build_event.h's own comments on each duplicated macro); these checks are
 * what keep the duplicates from silently drifting instead. */
typedef char pipeline_build_event_base32_len_check[
    (PIPELINE_BUILT_BASE32_LEN == PIPELINE_BASE32_ENCODED_LEN(PIPELINE_BUILT_PAYLOAD_SIZE)) ? 1 : -1];
typedef char pipeline_build_event_qr_data_codewords_check[
    (PIPELINE_BUILT_QR_DATA_CODEWORDS == PIPELINE_QR_DATA_CODEWORDS) ? 1 : -1];
/* Cross-checks for build_event.h's hand-duplicated PIPELINE_BUILT_BYTE_SEG_
 * HEADER_BITS(12)/PIPELINE_BUILT_ALNUM_SEG_HEADER_BITS(13) (spec #122,
 * sub-issue #123): each single-segment ceiling qr_adapter.h independently
 * derives (PIPELINE_QR_MAX_PAYLOAD_BYTES for BYTE mode,
 * PIPELINE_QR_ALNUM_MAX_CHARS for ALPHANUMERIC mode) is recomputed here
 * from the SAME raw data-bit budget minus only that one segment's own
 * header-bit constant -- if either duplicated header-bit width ever
 * drifts from the QR spec's real per-mode character-count field width,
 * this recomputation stops matching qr_adapter.h's own independently
 * pinned value and fails loudly here, at compile time. */
typedef char pipeline_build_event_byte_seg_header_bits_check[
    (((long)PIPELINE_BUILT_QR_DATA_CODEWORDS * 8L - (long)PIPELINE_BUILT_BYTE_SEG_HEADER_BITS) / 8L
     == (long)PIPELINE_QR_MAX_PAYLOAD_BYTES) ? 1 : -1];
typedef char pipeline_build_event_alnum_seg_header_bits_check[
    (PIPELINE_ALNUM_CHARS_FOR_BITS((long)PIPELINE_BUILT_QR_DATA_CODEWORDS * 8L -
                                    (long)PIPELINE_BUILT_ALNUM_SEG_HEADER_BITS)
     == (pipeline_u32)PIPELINE_QR_ALNUM_MAX_CHARS) ? 1 : -1];
/* This build's own PIPELINE_URL_BASE must leave room for at least one
 * base32 character per fragment -- a longer base URL than this build's
 * fixed two-segment QR bit budget allows is a build-time configuration
 * error, not a runtime one (mirrors the tag/name-length checks above:
 * loud, not silent). PIPELINE_BUILT_ALNUM_BUDGET_BITS is already computed
 * in signed `long` arithmetic (build_event.h's own comment) so an
 * over-long PIPELINE_URL_BASE that would otherwise wrap an unsigned
 * subtraction into a huge positive value can never masquerade as a valid
 * budget here. */
typedef char pipeline_build_event_fragment_budget_check[
    (PIPELINE_BUILT_ALNUM_BUDGET_BITS >= PIPELINE_BUILT_MIN_ALNUM_BUDGET_BITS) ? 1 : -1];

int build_event(const StarCapture *capture, const pipeline_u8 key[PIPELINE_KEY_SIZE], BuiltEvent *out)
{
    pipeline_u8 id[PIPELINE_EVENT_ID_SIZE];
    pipeline_u8 sig[PIPELINE_SCHNORR_SIG_SIZE];
    static const pipeline_u8 kPubkey[PIPELINE_FMT_SIZE_PUBKEY] = PIPELINE_EVENT_PUBKEY_BYTES;
    static const pipeline_u8 kTag[] = PIPELINE_EVENT_TAG_1_VALUE;
    /* Format v3's baked event name (spec #109, sub-issue #111): the same
     * PIPELINE_EVENT_NAME event_id.c's pipeline_event_serialize() already
     * folds into the signed ["n",...] tag is now packed onto the wire too,
     * so the packed payload and the signed serialization can never disagree
     * on the name -- retires the old display-only contract (#76). */
    static const pipeline_u8 kName[] = PIPELINE_EVENT_NAME;
    pipeline_u32 packedLen;

    pipeline_event_compute_id(capture, id);

    if (!pipeline_schnorr_sign(id, key, sig)) {
        return 0;
    }

    packedLen = pipeline_pack(capture, (pipeline_u32)PIPELINE_EVENT_CREATED_AT, kPubkey,
                               kTag, (pipeline_u8)PIPELINE_EVENT_TAG_1_LEN,
                               kName, (pipeline_u8)PIPELINE_EVENT_NAME_LEN, sig, out->packed_payload);
    if (packedLen != (pipeline_u32)PIPELINE_BUILT_PAYLOAD_SIZE) {
        return 0;
    }

    /*
     * ADR-0006 multi-frame transport (spec #115, sub-issue #116; realigned
     * to #101's ratified URL schema by spec #122, sub-issue #123): wrap the
     * unchanged packed_payload bytes above in the reversible base32 /
     * fragment / URL / two-segment-QR envelope -- see build_event.h's own
     * comment on this section's fixed compile-time sizing.
     */
    {
        static const pipeline_u8 kUrlBase[] = PIPELINE_URL_BASE;
        pipeline_u8 base32Text[PIPELINE_BUILT_BASE32_LEN];
        pipeline_u32 base32Len;
        pipeline_u32 frameCount;
        pipeline_u32 i;

        base32Len = pipeline_base32_encode(out->packed_payload, packedLen, base32Text,
                                            (pipeline_u32)PIPELINE_BUILT_BASE32_LEN);
        if (base32Len != (pipeline_u32)PIPELINE_BUILT_BASE32_LEN) {
            return 0;
        }

        frameCount = pipeline_fragment_count(base32Len, (pipeline_u32)PIPELINE_BUILT_FRAGMENT_BUDGET);
        if (frameCount != (pipeline_u32)PIPELINE_BUILT_FRAME_COUNT) {
            return 0;
        }

        for (i = 0; i < frameCount; i++) {
            pipeline_u8 fragment[PIPELINE_BUILT_FRAGMENT_BUDGET];
            pipeline_u32 fragmentLen;
            pipeline_u8 url[PIPELINE_BUILT_URL_MAX_LEN];
            pipeline_u32 urlLen;

            if (!pipeline_fragment_build(base32Text, base32Len, (pipeline_u32)PIPELINE_BUILT_FRAGMENT_BUDGET,
                                          i, frameCount, fragment, &fragmentLen)) {
                return 0;
            }

            urlLen = pipeline_url_wrap(kUrlBase, (pipeline_u32)PIPELINE_URL_BASE_LEN, fragment, fragmentLen,
                                        url, (pipeline_u32)PIPELINE_BUILT_URL_MAX_LEN);
            if (urlLen == 0) {
                return 0;
            }

            /* Two-segment QR encode (spec #122, sub-issue #123): the
             * verbatim "<BASE>#" prefix rides a BYTE segment, and the
             * `/`-delimited SEQ/TOTAL/PAYLOAD fragment tail immediately
             * following it in url[] rides ALPHANUMERIC -- see
             * PIPELINE_BUILT_URL_BYTE_SEG_LEN's own comment (build_event.h)
             * for why the split point is exactly that length. */
            if (!pipeline_qr_encode_two_segment(url, (pipeline_u32)PIPELINE_BUILT_URL_BYTE_SEG_LEN,
                                                 url + (pipeline_u32)PIPELINE_BUILT_URL_BYTE_SEG_LEN,
                                                 urlLen - (pipeline_u32)PIPELINE_BUILT_URL_BYTE_SEG_LEN,
                                                 out->qr_bitmaps[i])) {
                return 0;
            }
        }

        out->frame_count = frameCount;
    }

    return 1;
}
