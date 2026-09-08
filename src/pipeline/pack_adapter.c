/*
 * See pack_adapter.h. Both functions write/read fields one byte at a time
 * at descriptor-derived offsets, never via memcpy/struct-layout, mirroring
 * the same explicit-serialization discipline build_event.h documents for
 * the eventual real serialize stage.
 */

#include "pack_adapter.h"
#include "byteorder.h"

void pipeline_pack(const StarCapture *capture,
                    const pipeline_u8 sig[PIPELINE_FMT_SIZE_SIG],
                    pipeline_u8 out[PIPELINE_PACKED_SIZE])
{
    pipeline_u32 i;

    pipeline_write_u8(out, PIPELINE_FMT_OFF_FORMAT_TAG, (pipeline_u8)PIPELINE_FMT_TAG_VALUE);
    pipeline_write_u8(out, PIPELINE_FMT_OFF_COURSE, capture->course);
    pipeline_write_u8(out, PIPELINE_FMT_OFF_ACT, capture->act);
    pipeline_write_u8(out, PIPELINE_FMT_OFF_COINS, capture->coins);
    pipeline_write_u32_be(out, PIPELINE_FMT_OFF_FRAMES, capture->frames);
    pipeline_write_u16_be(out, PIPELINE_FMT_OFF_NONCE16, capture->nonce16);
    pipeline_write_u8(out, PIPELINE_FMT_OFF_KEY_ID, capture->keyId);

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
    capture_out->frames  = pipeline_read_u32_be(in, PIPELINE_FMT_OFF_FRAMES);
    capture_out->nonce16 = pipeline_read_u16_be(in, PIPELINE_FMT_OFF_NONCE16);
    capture_out->keyId   = in[PIPELINE_FMT_OFF_KEY_ID];

    for (i = 0; i < PIPELINE_FMT_SIZE_SIG; i++) {
        sig_out[i] = in[PIPELINE_FMT_OFF_SIG + i];
    }

    return 0;
}
