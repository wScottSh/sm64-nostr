/*
 * See base32.h. Pure C89: no MarioState, no globals, no N64 headers, no
 * C99 syntax.
 */

#include "base32.h"

pipeline_u32 pipeline_base32_encode(const pipeline_u8 *in, pipeline_u32 inLen,
                                     pipeline_u8 *out, pipeline_u32 outCap)
{
    static const char alphabet[] = PIPELINE_BASE32_ALPHABET;
    pipeline_u32 outLen;
    pipeline_u32 bitBuf;
    pipeline_u32 bitCount;
    pipeline_u32 outPos;
    pipeline_u32 i;

    outLen = PIPELINE_BASE32_ENCODED_LEN(inLen);
    if (outLen > outCap) {
        return 0;
    }

    bitBuf = 0;
    bitCount = 0;
    outPos = 0;

    for (i = 0; i < inLen; i++) {
        bitBuf = (bitBuf << 8) | (pipeline_u32)in[i];
        bitCount += 8;
        while (bitCount >= 5) {
            bitCount -= 5;
            out[outPos] = (pipeline_u8)alphabet[(bitBuf >> bitCount) & 0x1Fu];
            outPos++;
        }
        /* Drop the already-emitted high bits so bitBuf never grows past a
         * few leftover bits -- without this, the left shift above would
         * accumulate every input byte's bits forever and overflow. */
        bitBuf &= (bitCount > 0) ? ((1u << bitCount) - 1u) : 0u;
    }

    if (bitCount > 0) {
        out[outPos] = (pipeline_u8)alphabet[(bitBuf << (5 - bitCount)) & 0x1Fu];
        outPos++;
    }

    return outPos;
}

int pipeline_base32_decode(const pipeline_u8 *in, pipeline_u32 inLen,
                            pipeline_u8 *out, pipeline_u32 outCap, pipeline_u32 *outLen)
{
    static const char alphabet[] = PIPELINE_BASE32_ALPHABET;
    pipeline_u32 bitBuf;
    pipeline_u32 bitCount;
    pipeline_u32 outPos;
    pipeline_u32 i;
    int j;
    int value;

    bitBuf = 0;
    bitCount = 0;
    outPos = 0;

    for (i = 0; i < inLen; i++) {
        value = -1;
        for (j = 0; j < (int)PIPELINE_BASE32_ALPHABET_LEN; j++) {
            if ((pipeline_u8)alphabet[j] == in[i]) {
                value = j;
                break;
            }
        }
        if (value < 0) {
            return 0;
        }

        bitBuf = (bitBuf << 5) | (pipeline_u32)value;
        bitCount += 5;
        if (bitCount >= 8) {
            bitCount -= 8;
            if (outPos >= outCap) {
                return 0;
            }
            out[outPos] = (pipeline_u8)((bitBuf >> bitCount) & 0xFFu);
            outPos++;
        }
        bitBuf &= (bitCount > 0) ? ((1u << bitCount) - 1u) : 0u;
    }

    *outLen = outPos;
    return 1;
}
