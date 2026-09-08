#ifndef PIPELINE_BUILD_EVENT_H
#define PIPELINE_BUILD_EVENT_H

/*
 * The pipeline's pure interface: build_event(StarCapture, key) -> BuiltEvent.
 * See spec #24 / sub-issue #25 (walking skeleton) and sub-issue #30 (real
 * interface: this is where the serialize -> SHA-256 id -> Schnorr sign ->
 * pack -> QR encode chain is actually wired together).
 *
 * This module must never include MarioState, game globals, or any N64
 * header -- it is compiled twice, unmodified, into both the ROM build and
 * the host test tool (tools/pipeline_test). It defines its own fixed-width
 * types below instead of depending on <stdint.h> (unavailable under the ROM
 * build's -nostdinc) or the decomp's own N64 types.h.
 *
 * Also pulls in format_descriptor.h for its size macro only
 * (PIPELINE_FMT_TOTAL_SIZE, which PIPELINE_BUILT_PAYLOAD_SIZE below is
 * built from) -- the SAME generated, single-source-of-truth constant
 * pack_adapter.h's own PIPELINE_PACKED_SIZE is built from and
 * pipeline_pack()/pipeline_unpack() actually use, never a hand-duplicated
 * literal that could silently drift.
 *
 * Deliberately included here rather than via pack_adapter.h directly:
 * pack_adapter.h itself #includes "build_event.h" (for StarCapture/
 * pipeline_u8), so if THIS file included pack_adapter.h back, a
 * translation unit that happens to #include "pack_adapter.h" FIRST would
 * open PIPELINE_PACK_ADAPTER_H's own include guard, then reach its nested
 * #include "build_event.h" -- which proceeds normally (this file's own
 * guard, PIPELINE_BUILD_EVENT_H, isn't set yet) and, partway through,
 * reaches THIS #include "pack_adapter.h" line -- which DOES no-op, because
 * PIPELINE_PACK_ADAPTER_H is already open from the outermost include.
 * PIPELINE_PACKED_SIZE (defined later in pack_adapter.h, after that
 * no-op'd include) never gets defined, so referencing it below would be an
 * undeclared-identifier error. format_descriptor.h has no such cycle (it
 * never includes build_event.h), so going one level lower, straight to the
 * generated header, avoids the problem entirely.
 */
#include "format_descriptor.h"

typedef unsigned char  pipeline_u8;
typedef unsigned short pipeline_u16;
typedef unsigned int   pipeline_u32;

/*
 * Plain-old-data capture of the inputs needed to build a star-grab event.
 * Filled entirely by N64-side capture glue at interact_star_or_key; the
 * pipeline itself never reads course/act globals, MarioState, or timers.
 *
 * Fields are serialized explicitly, one at a time, by the (future) real
 * serialize stage -- never via memcpy/struct-layout -- so host/target
 * struct padding and endianness differences can never leak into the wire
 * format. Don't rely on this struct's in-memory layout for anything.
 */
typedef struct StarCapture {
    pipeline_u8  course;
    pipeline_u8  act;
    pipeline_u8  coins;
    pipeline_u32 frames;
    pipeline_u16 nonce16;
    pipeline_u8  keyId;
} StarCapture;

#define PIPELINE_KEY_SIZE 32

#define PIPELINE_BUILT_PAYLOAD_SIZE PIPELINE_FMT_TOTAL_SIZE

/*
 * QR bitmap buffer sizing: mirrors qrcodegen_BUFFER_LEN_FOR_VERSION(7) --
 * ((version*4+17)^2 + 7) / 8 + 1 -- from qrcodegen.h/qr_adapter.h's fixed
 * version 7 choice (spec #52, sub-issue #53), WITHOUT #including
 * qrcodegen.h here. qr_adapter.h's own header comment documents that
 * qrcodegen.h/qrcodegen.c must stay hidden behind the qr_adapter.h seam
 * (never visible to callers outside src/pipeline/, including game glue,
 * #31/#32) -- #including it from this file, which every pipeline-internal
 * header transitively pulls in via StarCapture/pipeline_u8, would leak
 * qrcodegen's whole public surface (qrcodegen_encodeBinary, its enums, ...)
 * to every build_event.h consumer. build_event.c's own compile-time checks
 * (comparing PIPELINE_BUILT_QR_VERSION/PIPELINE_BUILT_QR_BITMAP_SIZE
 * against qr_adapter.h's PIPELINE_QR_VERSION/PIPELINE_QR_BUFFER_LEN) are
 * what keep this duplicated formula from silently drifting instead.
 */
#define PIPELINE_BUILT_QR_VERSION 7
#define PIPELINE_BUILT_QR_BITMAP_SIZE \
    ((((PIPELINE_BUILT_QR_VERSION) * 4 + 17) * ((PIPELINE_BUILT_QR_VERSION) * 4 + 17) + 7) / 8 + 1)

/*
 * The pipeline's real output (spec #24, sub-issue #30): the packed payload
 * (1-byte format tag + StarCapture's fields + 64-byte Schnorr signature, per
 * format_descriptor.json -- currently 75 B, comfortably inside the ~88 B
 * spine) and the QR bitmap it was encoded into (qrcodegen format; read via
 * pipeline_qr_get_size()/pipeline_qr_get_module(), see qr_adapter.h).
 */
typedef struct BuiltEvent {
    pipeline_u8 packed_payload[PIPELINE_BUILT_PAYLOAD_SIZE];
    pipeline_u8 qr_bitmap[PIPELINE_BUILT_QR_BITMAP_SIZE];
} BuiltEvent;

/*
 * build_event: the pipeline's one interface. Pure and deterministic given
 * (capture, key) -- touches no globals, no timers, no I/O, no MarioState.
 * Chains, internally: canonical NIP-01 serialize + SHA-256 id
 * (event_id.h) -> BIP-340 Schnorr sign of that id with key (schnorr_adapter.h)
 * -> pack capture's fields + the signature into the wire payload
 * (pack_adapter.h) -> QR-encode that payload (qr_adapter.h). capture's
 * nonce16 is an INPUT field (StarCapture), not computed here -- deriving it
 * from capture-time entropy is capture glue's job (#31), out of scope for
 * this pure module.
 *
 * Returns nonzero (true) on success, writing both out->packed_payload and
 * out->qr_bitmap. Returns 0 (false) only in the two documented failure
 * cases inherited from the internal seams this chains together:
 * pipeline_schnorr_sign()'s astronomically-unlikely out-of-range-key/
 * zero-nonce cases (schnorr_adapter.h) -- in which case out is left
 * entirely untouched -- or pipeline_qr_encode()'s over-budget rejection
 * (qr_adapter.h), which can only happen if PIPELINE_BUILT_PAYLOAD_SIZE ever
 * grows past PIPELINE_QR_MAX_PAYLOAD_BYTES (not with today's fixed 75 B
 * format descriptor); in that second case out->packed_payload has ALREADY
 * been written (pipeline_pack() ran first) even though the call overall
 * failed, and out->qr_bitmap is left at qr_adapter.h's own documented
 * invalid-size sentinel (qr_bitmap[0] == 0), not a usable bitmap. Either
 * way, callers must check the return value and never treat out as valid on
 * failure, but out->packed_payload specifically is not "meaningless" on
 * the second failure path -- it just doesn't matter, because the call as a
 * whole must still be treated as failed.
 */
int build_event(const StarCapture *capture, const pipeline_u8 key[PIPELINE_KEY_SIZE], BuiltEvent *out);

#endif /* PIPELINE_BUILD_EVENT_H */
