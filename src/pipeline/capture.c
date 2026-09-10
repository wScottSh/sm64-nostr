/*
 * See capture.h. The 12-byte nonce-input buffer is built one explicit byte
 * at a time (never memcpy/struct-layout), the same discipline
 * pack_adapter.c/event_id.c document for their own serialization.
 *
 * write_u16_be/write_u32_be below are intentionally kept as local file-static
 * copies of pack_adapter.c's identically-shaped helpers rather than shared
 * from a common header: this translation unit compiles under the whole-build
 * COMPILER (COMPILER=ido by default -- a C89 compiler), so a shared header
 * could not use `static inline` (C99) and a plain `static` helper header
 * would emit unused-function warnings in whichever TU didn't call all of
 * them. The pipeline's pure objects are deliberately C89/IDO-clean (see the
 * root Makefile's PIPELINE_ROM_OBJS comment); a five-line duplicated writer
 * is the smaller cost.
 */

#include "capture.h"
#include "sha256.h"

#define PIPELINE_CAPTURE_NONCE_INPUT_SIZE 12

static void write_u32_be(pipeline_u8 *out, pipeline_u32 offset, pipeline_u32 value)
{
    out[offset]     = (pipeline_u8)((value >> 24) & 0xFF);
    out[offset + 1] = (pipeline_u8)((value >> 16) & 0xFF);
    out[offset + 2] = (pipeline_u8)((value >> 8) & 0xFF);
    out[offset + 3] = (pipeline_u8)(value & 0xFF);
}

static void write_u16_be(pipeline_u8 *out, pipeline_u32 offset, pipeline_u16 value)
{
    out[offset]     = (pipeline_u8)((value >> 8) & 0xFF);
    out[offset + 1] = (pipeline_u8)(value & 0xFF);
}

static pipeline_u16 pipeline_capture_hash_nonce(pipeline_u32 osCount,
                                                 pipeline_u32 globalTimer,
                                                 pipeline_u8 rawStickX,
                                                 pipeline_u8 rawStickY,
                                                 pipeline_u16 buttonMask)
{
    pipeline_u8 input[PIPELINE_CAPTURE_NONCE_INPUT_SIZE];
    pipeline_u8 digest[PIPELINE_SHA256_DIGEST_SIZE];

    write_u32_be(input, 0, osCount);
    write_u32_be(input, 4, globalTimer);
    input[8] = rawStickX;
    input[9] = rawStickY;
    write_u16_be(input, 10, buttonMask);

    pipeline_sha256(input, PIPELINE_CAPTURE_NONCE_INPUT_SIZE, digest);

    /* First 16 bits (2 bytes) of the digest, big-endian. */
    return (pipeline_u16)(((pipeline_u16)digest[0] << 8) | (pipeline_u16)digest[1]);
}

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
                             StarCapture *out)
{
    out->course  = course;
    out->act     = act;
    out->coins   = coins;
    out->frames  = frames;
    out->keyId   = starIndex;
    out->nonce16 = pipeline_capture_hash_nonce(osCount, globalTimer, rawStickX, rawStickY, buttonMask);
}

pipeline_u32 pipeline_select_frames(pipeline_u8 courseNum,
                                     pipeline_u8 starIndex,
                                     pipeline_u32 globalTimer,
                                     pipeline_u32 courseStartFrame)
{
    /* #113 slots the MIPS star-index 3/4 (course-less basement grab)
     * branch in here; not added by this ticket. */
    (void)starIndex;

    if (courseNum != PIPELINE_COURSE_NONE) {
        /* Any real course (main + secret/bonus, incl. PSS). */
        return globalTimer - courseStartFrame;
    }

    /* Sentinel: no in-course time. A legitimate grab always costs > 0
     * frames (control-gain precedes the grab), so 0 never collides with a
     * real time. */
    return 0;
}
