/*
 * See fragment.h. Pure C89: no MarioState, no globals, no N64 headers, no
 * C99 syntax.
 */

#include "fragment.h"

static void encode_base36_field(pipeline_u32 value, pipeline_u32 fieldLen, pipeline_u8 *out)
{
    static const char alphabet[] = PIPELINE_FRAGMENT_BASE36_ALPHABET;
    pipeline_u32 i;

    for (i = fieldLen; i > 0; i--) {
        out[i - 1] = (pipeline_u8)alphabet[value % (pipeline_u32)PIPELINE_FRAGMENT_BASE36_LEN];
        value /= (pipeline_u32)PIPELINE_FRAGMENT_BASE36_LEN;
    }
}

static int base36_value(pipeline_u8 c)
{
    if (c >= (pipeline_u8)'0' && c <= (pipeline_u8)'9') {
        return (int)(c - (pipeline_u8)'0');
    }
    if (c >= (pipeline_u8)'A' && c <= (pipeline_u8)'Z') {
        return (int)(c - (pipeline_u8)'A') + 10;
    }
    return -1;
}

static int decode_base36_field(const pipeline_u8 *in, pipeline_u32 fieldLen, pipeline_u32 *out)
{
    pipeline_u32 value;
    pipeline_u32 i;
    int digit;

    value = 0;
    for (i = 0; i < fieldLen; i++) {
        digit = base36_value(in[i]);
        if (digit < 0) {
            return 0;
        }
        value = value * (pipeline_u32)PIPELINE_FRAGMENT_BASE36_LEN + (pipeline_u32)digit;
    }
    *out = value;
    return 1;
}

pipeline_u32 pipeline_fragment_count(pipeline_u32 base32Len, pipeline_u32 perFrameBudget)
{
    pipeline_u32 chunkCap;
    pipeline_u32 count;

    if (perFrameBudget <= (pipeline_u32)PIPELINE_FRAGMENT_HEADER_LEN) {
        return 0;
    }
    chunkCap = perFrameBudget - (pipeline_u32)PIPELINE_FRAGMENT_HEADER_LEN;

    if (base32Len == 0) {
        return 1;
    }

    count = (base32Len + chunkCap - 1) / chunkCap;
    if (count > (pipeline_u32)PIPELINE_FRAGMENT_MAX_COUNT) {
        return 0;
    }
    return count;
}

int pipeline_fragment_build(const pipeline_u8 *base32Text, pipeline_u32 base32Len,
                             pipeline_u32 perFrameBudget, pipeline_u32 frameIndex,
                             pipeline_u32 frameCount, pipeline_u8 *out, pipeline_u32 *outLen)
{
    pipeline_u32 chunkCap;
    pipeline_u32 start;
    pipeline_u32 end;
    pipeline_u32 chunkLen;
    pipeline_u32 i;

    if (perFrameBudget <= (pipeline_u32)PIPELINE_FRAGMENT_HEADER_LEN) {
        return 0;
    }
    if (frameCount == 0 || frameCount > (pipeline_u32)PIPELINE_FRAGMENT_MAX_COUNT || frameIndex >= frameCount) {
        return 0;
    }

    chunkCap = perFrameBudget - (pipeline_u32)PIPELINE_FRAGMENT_HEADER_LEN;
    start = frameIndex * chunkCap;
    if (start > base32Len) {
        return 0;
    }
    end = start + chunkCap;
    if (end > base32Len) {
        end = base32Len;
    }
    chunkLen = end - start;

    encode_base36_field(frameIndex, (pipeline_u32)PIPELINE_FRAGMENT_INDEX_LEN, out);
    out[PIPELINE_FRAGMENT_INDEX_LEN] = (pipeline_u8)PIPELINE_URL_FIELD_SEP[0];
    encode_base36_field(frameCount, (pipeline_u32)PIPELINE_FRAGMENT_COUNT_LEN,
                       out + PIPELINE_FRAGMENT_INDEX_LEN + (pipeline_u32)PIPELINE_URL_FIELD_SEP_LEN);
    out[(pipeline_u32)PIPELINE_FRAGMENT_INDEX_LEN + (pipeline_u32)PIPELINE_URL_FIELD_SEP_LEN +
        (pipeline_u32)PIPELINE_FRAGMENT_COUNT_LEN] = (pipeline_u8)PIPELINE_URL_FIELD_SEP[0];
    for (i = 0; i < chunkLen; i++) {
        out[(pipeline_u32)PIPELINE_FRAGMENT_HEADER_LEN + i] = base32Text[start + i];
    }
    *outLen = (pipeline_u32)PIPELINE_FRAGMENT_HEADER_LEN + chunkLen;
    return 1;
}

int pipeline_fragment_parse_header(const pipeline_u8 *fragment, pipeline_u32 fragmentLen,
                                    pipeline_u32 *frameIndexOut, pipeline_u32 *frameCountOut)
{
    pipeline_u8 sepByte = (pipeline_u8)PIPELINE_URL_FIELD_SEP[0];
    pipeline_u32 countFieldStart = (pipeline_u32)PIPELINE_FRAGMENT_INDEX_LEN + (pipeline_u32)PIPELINE_URL_FIELD_SEP_LEN;
    pipeline_u32 idx;
    pipeline_u32 cnt;

    if (fragmentLen < (pipeline_u32)PIPELINE_FRAGMENT_HEADER_LEN) {
        return 0;
    }
    if (fragment[PIPELINE_FRAGMENT_INDEX_LEN] != sepByte) {
        return 0;
    }
    if (fragment[countFieldStart + (pipeline_u32)PIPELINE_FRAGMENT_COUNT_LEN] != sepByte) {
        return 0;
    }
    if (!decode_base36_field(fragment, (pipeline_u32)PIPELINE_FRAGMENT_INDEX_LEN, &idx)) {
        return 0;
    }
    if (!decode_base36_field(fragment + countFieldStart,
                            (pipeline_u32)PIPELINE_FRAGMENT_COUNT_LEN, &cnt)) {
        return 0;
    }
    if (cnt == 0 || idx >= cnt) {
        return 0;
    }
    *frameIndexOut = idx;
    *frameCountOut = cnt;
    return 1;
}
