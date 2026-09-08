/*
 * build_event -- the pipeline's real interface (spec #24, sub-issue #30).
 *
 * Wires the internal seams landed in #26-#29 together, in order: canonical
 * NIP-01 serialize + SHA-256 id (event_id.h) -> BIP-340 Schnorr sign of that
 * id (schnorr_adapter.h) -> pack capture's fields + the signature into the
 * wire payload (pack_adapter.h) -> QR-encode that payload (qr_adapter.h).
 * See build_event.h for the full interface contract.
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
 * format_descriptor.json's total size or qr_adapter.h's fixed QR version
 * ever change without updating build_event.h to match, these fail to
 * compile (negative array size) instead of silently sizing BuiltEvent
 * wrong. */
typedef char pipeline_build_event_payload_size_check[
    (PIPELINE_BUILT_PAYLOAD_SIZE == PIPELINE_PACKED_SIZE) ? 1 : -1];
typedef char pipeline_build_event_qr_version_check[
    (PIPELINE_BUILT_QR_VERSION == PIPELINE_QR_VERSION) ? 1 : -1];
typedef char pipeline_build_event_qr_bitmap_size_check[
    (PIPELINE_BUILT_QR_BITMAP_SIZE == PIPELINE_QR_BUFFER_LEN) ? 1 : -1];

int build_event(const StarCapture *capture, const pipeline_u8 key[PIPELINE_KEY_SIZE], BuiltEvent *out)
{
    pipeline_u8 id[PIPELINE_EVENT_ID_SIZE];
    pipeline_u8 sig[PIPELINE_SCHNORR_SIG_SIZE];

    pipeline_event_compute_id(capture, id);

    if (!pipeline_schnorr_sign(id, key, sig)) {
        return 0;
    }

    pipeline_pack(capture, sig, out->packed_payload);

    if (!pipeline_qr_encode(out->packed_payload, (pipeline_u32)PIPELINE_BUILT_PAYLOAD_SIZE, out->qr_bitmap)) {
        return 0;
    }

    return 1;
}
