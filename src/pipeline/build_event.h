#ifndef PIPELINE_BUILD_EVENT_H
#define PIPELINE_BUILD_EVENT_H

/*
 * The pipeline's pure interface: build_event(StarCapture, key) -> BuiltEvent.
 * See spec #24 / sub-issue #25.
 *
 * This module must never include MarioState, game globals, or any N64
 * header -- it is compiled twice, unmodified, into both the ROM build and
 * the host test tool (tools/pipeline_test). It defines its own fixed-width
 * types below instead of depending on <stdint.h> (unavailable under the ROM
 * build's -nostdinc) or the decomp's own N64 types.h.
 *
 * This sub-issue (#25) is the walking skeleton only: build_event has a
 * stub body. The real serialize -> SHA-256 -> Schnorr sign -> pack -> QR
 * encode chain lands in later sub-issues.
 */

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

#define PIPELINE_KEY_SIZE          32
#define PIPELINE_STUB_PAYLOAD_SIZE 4

typedef struct BuiltEvent {
    pipeline_u8 payload[PIPELINE_STUB_PAYLOAD_SIZE];
} BuiltEvent;

/*
 * build_event: pure stub for the walking skeleton. Deterministic given
 * (capture, key); touches no globals, no timers, no I/O.
 */
void build_event(const StarCapture *capture, const pipeline_u8 key[PIPELINE_KEY_SIZE], BuiltEvent *out);

#endif /* PIPELINE_BUILD_EVENT_H */
