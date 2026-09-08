#ifndef PIPELINE_BYTEORDER_H
#define PIPELINE_BYTEORDER_H

/*
 * Big-endian byte (de)serialization helpers shared by the pipeline's two
 * explicit-serialization sites: pack_adapter.c (the wire payload) and
 * capture.c (the content-nonce input buffer). Both write/read one byte at a
 * time at explicitly-computed offsets, never via memcpy/struct-layout, so
 * host/target struct padding and endianness never leak into a serialized
 * form. Kept here, as one shared definition, so the two sites can never
 * drift apart.
 *
 * Like every other src/pipeline header this is pure: no MarioState, no
 * globals, no N64 headers -- it is compiled a second time, unmodified, into
 * the host test tool (tools/pipeline_test). It depends only on the
 * fixed-width pipeline_u8/u16/u32 types from build_event.h.
 *
 * The helpers are `static inline`: internal linkage per translation unit (no
 * multiple-definition across the TUs that include this), and any that a
 * given TU does not use are dropped without an unused-function warning.
 */
#include "build_event.h"

static inline void pipeline_write_u8(pipeline_u8 *out, pipeline_u32 offset, pipeline_u8 value)
{
    out[offset] = value;
}

static inline void pipeline_write_u16_be(pipeline_u8 *out, pipeline_u32 offset, pipeline_u16 value)
{
    out[offset]     = (pipeline_u8)((value >> 8) & 0xFF);
    out[offset + 1] = (pipeline_u8)(value & 0xFF);
}

static inline void pipeline_write_u32_be(pipeline_u8 *out, pipeline_u32 offset, pipeline_u32 value)
{
    out[offset]     = (pipeline_u8)((value >> 24) & 0xFF);
    out[offset + 1] = (pipeline_u8)((value >> 16) & 0xFF);
    out[offset + 2] = (pipeline_u8)((value >> 8) & 0xFF);
    out[offset + 3] = (pipeline_u8)(value & 0xFF);
}

static inline pipeline_u16 pipeline_read_u16_be(const pipeline_u8 *in, pipeline_u32 offset)
{
    return (pipeline_u16)(((pipeline_u16)in[offset] << 8) | (pipeline_u16)in[offset + 1]);
}

static inline pipeline_u32 pipeline_read_u32_be(const pipeline_u8 *in, pipeline_u32 offset)
{
    return ((pipeline_u32)in[offset] << 24) | ((pipeline_u32)in[offset + 1] << 16) |
           ((pipeline_u32)in[offset + 2] << 8) | (pipeline_u32)in[offset + 3];
}

#endif /* PIPELINE_BYTEORDER_H */
