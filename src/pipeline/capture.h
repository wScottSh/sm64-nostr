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
 * keyId is BOTH packed into the wire payload (pack_adapter.c's KEY_ID field)
 * AND serialized into the signed content (event_id.c's
 * pipeline_event_build_content(), key order
 * {course, act, coins, frames, nonce, keyId}) -- so a tampered keyId no
 * longer verifies against the original Schnorr signature. This closes the
 * tamper-evidence hole for stars where `act` alone doesn't identify which
 * star was grabbed (100-coin/secret-course stars), where keyId is
 * load-bearing star identity, honoring #24's "no chance to tamper" problem
 * statement (user story 1).
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

/*
 * PIPELINE_COURSE_NONE: the pure pipeline never includes game headers
 * (course_table.h), so this mirrors COURSE_NONE (levels/course_defines.h,
 * enum value 0 -- the Castle Grounds course hub, i.e. "not in a real
 * course") as a plain numeric constant local to the pipeline's own seam.
 */
#define PIPELINE_COURSE_NONE 0

/*
 * PIPELINE_STAR_INDEX_ACT_4/5: mirrors STAR_INDEX_ACT_4/5
 * (include/object_constants.h, values 3/4) -- the MIPS stars (1 & 2), which
 * the pipeline's pure code cannot include the game header for. This is the
 * starIndex value carried in keyId (o->oBhvParams >> 24 & 0x1F at the grab
 * site) for those two stars specifically.
 */
#define PIPELINE_STAR_INDEX_ACT_4 3
#define PIPELINE_STAR_INDEX_ACT_5 4

/*
 * pipeline_select_frames: the pure frames-selection helper (format-v3
 * spec.md §3.4, spec #109 sub-issues #112/#113 -- the ONE new seam that
 * spec proposes). Takes every input the grab-site branch needs as plain
 * parameters -- courseNum, starIndex, the live globalTimer read, and the
 * course/room-entry snapshot -- and returns the `frames` value the wire
 * payload's FRAMES field carries. The gGlobalTimer snapshot-on-entry itself
 * (src/game/level_update.c's sCourseStartFrame) is N64 glue and is verified
 * on-device, not host-tested; this is the pure decision on top of it.
 *
 * Three cases, matching the spec's pseudo-code exactly:
 *   - real course (courseNum != PIPELINE_COURSE_NONE): elapsed in-course
 *     frames, globalTimer - courseStartFrame.
 *   - MIPS stars 1 & 2 (courseNum == PIPELINE_COURSE_NONE and starIndex is
 *     PIPELINE_STAR_INDEX_ACT_4 or _ACT_5, #113): elapsed since the guarded
 *     LEVEL_CASTLE-area-3 (basement) entry snapshot, globalTimer -
 *     courseStartFrame -- the SAME sCourseStartFrame storage the real-course
 *     branch reads, re-snapshotted on basement entry by the strictly-guarded
 *     area-change path in src/game/level_update.c (warp_area()). Whether
 *     that storage currently holds a course-start or a basement-entry
 *     snapshot is decided upstream by whichever of level_update.c's two
 *     snapshot sites most recently fired -- this helper makes no such
 *     choice itself; it only selects which of these three cases applies.
 *   - everything else: the 0 sentinel ("no in-course time" -- safe, since
 *     control-gain always precedes a grab, so a real time is always > 0).
 */
pipeline_u32 pipeline_select_frames(pipeline_u8 courseNum,
                                     pipeline_u8 starIndex,
                                     pipeline_u32 globalTimer,
                                     pipeline_u32 courseStartFrame);

#endif /* PIPELINE_CAPTURE_H */
