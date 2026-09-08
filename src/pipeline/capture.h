#ifndef PIPELINE_CAPTURE_H
#define PIPELINE_CAPTURE_H

/*
 * Capture-glue's pure half (spec #24, sub-issue #31): the field-extraction +
 * content-nonce hashing that fills a StarCapture from capture-time inputs.
 *
 * Like build_event.h/event_id.h/pack_adapter.h/qr_adapter.h, this file is
 * pure -- no MarioState, no game globals, no N64 headers, no timers read
 * internally. It takes every capture-time input as a plain parameter and is
 * compiled a second time, unmodified, into the host test tool
 * (tools/pipeline_test). This is the ONE place the content nonce is hashed;
 * the N64-side glue at interact_star_or_key (src/game/interaction.c) calls
 * this function with live values, and the host test calls it with fixed
 * vectors -- so nonce logic is never duplicated between the two (spec #24
 * sub-issue #31's acceptance criteria: "the nonce is computed in the glue,
 * not the pipeline -- no entropy source crosses into the pipeline" is
 * satisfied by having exactly one shared function do the hashing, called
 * from game glue with real entropy and from the host test with fixed
 * stand-ins for that same entropy).
 *
 * Content nonce (spec #24 #11/#21, sub-issue #31's acceptance criteria):
 *   nonce16 = first 16 BITS (the leading 2 bytes) of
 *             SHA256(osGetCount() || gGlobalTimer || rawStickX || rawStickY || buttonDown)
 * all captured at grab. Each field is appended big-endian, explicit byte at
 * a time (mirroring pack_adapter.c/event_id.c's own explicit-serialization
 * discipline -- never memcpy/struct-layout): osCount (4 bytes), globalTimer
 * (4 bytes), rawStickX (1 byte), rawStickY (1 byte), buttonMask (2 bytes) =
 * 12 bytes hashed total. nonce16 is then the first two digest bytes,
 * interpreted big-endian, packed into StarCapture's 16-bit nonce16 field.
 */

#include "build_event.h"

/*
 * pipeline_capture_build: fills out from capture-time inputs, hashing the
 * content nonce internally per the contract above. keyId carries the star
 * index (o->oBhvParams >> 24 & 0x1F at the grab site) -- StarCapture has no
 * separate "starIndex" field; keyId is the field the parent spec's
 * StarCapture shape ({course, act, coins, frames, nonce16, keyId}) provides
 * for it. Never called for Bowser-key grabs (#17) -- exclusion happens at
 * the call site (interact_star_or_key), before this function is ever
 * reached, not inside it: keyId's job here is only star-index carriage.
 *
 * KNOWN GAP (spec #24, flagged at sub-issue #31, owned by #28's content
 * shape): keyId travels in the packed wire payload (pack_adapter.c's
 * KEY_ID field) but is NOT part of the signed content
 * (event_id.c's pipeline_event_build_content() serializes only
 * {course, act, coins, frames, nonce}) -- so a tampered keyId still
 * verifies against the original Schnorr signature. For stars where `act`
 * alone doesn't identify which star was grabbed (100-coin/secret-course
 * stars), keyId is load-bearing, so this is a real tamper-evidence hole
 * against #24's "no chance to tamper" problem statement, not a cosmetic
 * one. Out of #31's scope (event_id.c's content shape is #28's, already
 * landed and pinned against independent id/signature oracles) -- tracked
 * as a follow-up against #28/#24, not fixed here.
 */
void pipeline_capture_build(pipeline_u8 course,
                             pipeline_u8 act,
                             pipeline_u8 coins,
                             pipeline_u32 frames,
                             pipeline_u8 starIndex,
                             pipeline_u32 osCount,
                             pipeline_u32 globalTimer,
                             pipeline_u8 rawStickX,
                             pipeline_u8 rawStickY,
                             pipeline_u16 buttonMask,
                             StarCapture *out);

#endif /* PIPELINE_CAPTURE_H */
