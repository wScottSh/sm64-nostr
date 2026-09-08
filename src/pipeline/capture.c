/*
 * See capture.h. The 12-byte nonce-input buffer is built one explicit byte
 * at a time (never memcpy/struct-layout), the same discipline
 * pack_adapter.c/event_id.c document for their own serialization.
 */

#include "capture.h"
#include "byteorder.h"
#include "sha256.h"

#define PIPELINE_CAPTURE_NONCE_INPUT_SIZE 12

static pipeline_u16 pipeline_capture_hash_nonce(pipeline_u32 osCount,
                                                 pipeline_u32 globalTimer,
                                                 pipeline_u8 rawStickX,
                                                 pipeline_u8 rawStickY,
                                                 pipeline_u16 buttonMask)
{
    pipeline_u8 input[PIPELINE_CAPTURE_NONCE_INPUT_SIZE];
    pipeline_u8 digest[PIPELINE_SHA256_DIGEST_SIZE];

    pipeline_write_u32_be(input, 0, osCount);
    pipeline_write_u32_be(input, 4, globalTimer);
    input[8] = rawStickX;
    input[9] = rawStickY;
    pipeline_write_u16_be(input, 10, buttonMask);

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
