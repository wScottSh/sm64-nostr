/*
 * build_event -- the pipeline's real interface (spec #24, sub-issue #30;
 * format v2 self-contained payload, spec #52 sub-issue #54).
 *
 * Wires the internal seams together, in order: canonical NIP-01 serialize +
 * SHA-256 id (event_id.h) -> BIP-340 Schnorr sign of that id
 * (schnorr_adapter.h) -> pack capture's fields + createdAt + pubkey + the
 * per-game tag + the signature into the wire payload (pack_adapter.h) ->
 * QR-encode that payload (qr_adapter.h). createdAt/pubkey/the per-game tag
 * are sourced from the generated event_profile.h -- the SAME baked values
 * event_id.c's pipeline_event_serialize() already uses for the signed
 * serialization, so the packed wire bytes and the signed content can never
 * disagree. See build_event.h for the full interface contract.
 */

#include "build_event.h"
#include "event_id.h"
#include "schnorr_adapter.h"
#include "pack_adapter.h"
#include "qr_adapter.h"

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
 * loud-not-silent failure this pipeline's own conventions call for. A tag
 * over budget would otherwise surface only as the QR-fits check below
 * failing with a confusing "over the QR ceiling" message rather than the
 * real "tag too long" cause. */
typedef char pipeline_build_event_tag_len_check[
    (PIPELINE_EVENT_TAG_1_LEN <= PIPELINE_PACK_MAX_TAG_LEN) ? 1 : -1];
typedef char pipeline_build_event_payload_fits_qr_check[
    (PIPELINE_BUILT_PAYLOAD_SIZE <= PIPELINE_QR_MAX_PAYLOAD_BYTES) ? 1 : -1];
typedef char pipeline_build_event_qr_version_check[
    (PIPELINE_BUILT_QR_VERSION == PIPELINE_QR_VERSION) ? 1 : -1];
typedef char pipeline_build_event_qr_bitmap_size_check[
    (PIPELINE_BUILT_QR_BITMAP_SIZE == PIPELINE_QR_BUFFER_LEN) ? 1 : -1];

int build_event(const StarCapture *capture, const pipeline_u8 key[PIPELINE_KEY_SIZE], BuiltEvent *out)
{
    pipeline_u8 id[PIPELINE_EVENT_ID_SIZE];
    pipeline_u8 sig[PIPELINE_SCHNORR_SIG_SIZE];
    static const pipeline_u8 kPubkey[PIPELINE_FMT_SIZE_PUBKEY] = PIPELINE_EVENT_PUBKEY_BYTES;
    static const pipeline_u8 kTag[] = PIPELINE_EVENT_TAG_1_VALUE;
    /* Format v3's NAME_LEN/NAME wire field is not yet threaded through this
     * build (spec #109, sub-issue #111 wires the real baked event name into
     * both the signed serialization and this pack call) -- sub-issue #110
     * only generalizes the descriptor/pack/unpack seam to carry it, so this
     * build packs a zero-length placeholder name for now. Deliberately not
     * the baked event-name macro (still off-wire here, per the honesty
     * invariant sub-issue #76 established; see event_id.c's own two-tag
     * serialization, unchanged by #110). */
    static const pipeline_u8 kName[] = "";
    pipeline_u32 packedLen;

    pipeline_event_compute_id(capture, id);

    if (!pipeline_schnorr_sign(id, key, sig)) {
        return 0;
    }

    packedLen = pipeline_pack(capture, (pipeline_u32)PIPELINE_EVENT_CREATED_AT, kPubkey,
                               kTag, (pipeline_u8)PIPELINE_EVENT_TAG_1_LEN,
                               kName, 0, sig, out->packed_payload);
    if (packedLen != (pipeline_u32)PIPELINE_BUILT_PAYLOAD_SIZE) {
        return 0;
    }

    if (!pipeline_qr_encode(out->packed_payload, packedLen, out->qr_bitmap)) {
        return 0;
    }

    return 1;
}
