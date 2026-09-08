/*
 * See pack_adapter.h. Both functions write/read fields one byte at a time
 * at descriptor-derived offsets, never via memcpy/struct-layout, mirroring
 * the same explicit-serialization discipline build_event.h documents for
 * the eventual real serialize stage.
 */

#include "pack_adapter.h"

static void write_u8(pipeline_u8 *out, pipeline_u32 offset, pipeline_u8 value)
{
    out[offset] = value;
}

static void write_u16_be(pipeline_u8 *out, pipeline_u32 offset, pipeline_u16 value)
{
    out[offset]     = (pipeline_u8)((value >> 8) & 0xFF);
    out[offset + 1] = (pipeline_u8)(value & 0xFF);
}

static void write_u32_be(pipeline_u8 *out, pipeline_u32 offset, pipeline_u32 value)
{
    out[offset]     = (pipeline_u8)((value >> 24) & 0xFF);
    out[offset + 1] = (pipeline_u8)((value >> 16) & 0xFF);
    out[offset + 2] = (pipeline_u8)((value >> 8) & 0xFF);
    out[offset + 3] = (pipeline_u8)(value & 0xFF);
}

static pipeline_u16 read_u16_be(const pipeline_u8 *in, pipeline_u32 offset)
{
    return (pipeline_u16)(((pipeline_u16)in[offset] << 8) | (pipeline_u16)in[offset + 1]);
}

static pipeline_u32 read_u32_be(const pipeline_u8 *in, pipeline_u32 offset)
{
    return ((pipeline_u32)in[offset] << 24) | ((pipeline_u32)in[offset + 1] << 16) |
           ((pipeline_u32)in[offset + 2] << 8) | (pipeline_u32)in[offset + 3];
}

void pipeline_pack(const StarCapture *capture,
                    const pipeline_u8 sig[PIPELINE_FMT_SIZE_SIG],
                    pipeline_u8 out[PIPELINE_PACKED_SIZE])
{
    pipeline_u32 i;

    write_u8(out, PIPELINE_FMT_OFF_FORMAT_TAG, (pipeline_u8)PIPELINE_FMT_TAG_VALUE);
    write_u8(out, PIPELINE_FMT_OFF_COURSE, capture->course);
    write_u8(out, PIPELINE_FMT_OFF_ACT, capture->act);
    write_u8(out, PIPELINE_FMT_OFF_COINS, capture->coins);
    write_u32_be(out, PIPELINE_FMT_OFF_FRAMES, capture->frames);
    write_u16_be(out, PIPELINE_FMT_OFF_NONCE16, capture->nonce16);
    write_u8(out, PIPELINE_FMT_OFF_KEY_ID, capture->keyId);

    for (i = 0; i < PIPELINE_FMT_SIZE_SIG; i++) {
        out[PIPELINE_FMT_OFF_SIG + i] = sig[i];
    }
}

int pipeline_unpack(const pipeline_u8 in[PIPELINE_PACKED_SIZE],
                     StarCapture *capture_out,
                     pipeline_u8 sig_out[PIPELINE_FMT_SIZE_SIG])
{
    pipeline_u32 i;

    if (in[PIPELINE_FMT_OFF_FORMAT_TAG] != (pipeline_u8)PIPELINE_FMT_TAG_VALUE) {
        return 1;
    }

    capture_out->course  = in[PIPELINE_FMT_OFF_COURSE];
    capture_out->act     = in[PIPELINE_FMT_OFF_ACT];
    capture_out->coins   = in[PIPELINE_FMT_OFF_COINS];
    capture_out->frames  = read_u32_be(in, PIPELINE_FMT_OFF_FRAMES);
    capture_out->nonce16 = read_u16_be(in, PIPELINE_FMT_OFF_NONCE16);
    capture_out->keyId   = in[PIPELINE_FMT_OFF_KEY_ID];

    for (i = 0; i < PIPELINE_FMT_SIZE_SIG; i++) {
        sig_out[i] = in[PIPELINE_FMT_OFF_SIG + i];
    }

    return 0;
}
