/*
 * See url.h. Pure C89: no MarioState, no globals, no N64 headers, no C99
 * syntax.
 */

#include "url.h"

pipeline_u32 pipeline_url_wrap(const pipeline_u8 *baseUrl, pipeline_u32 baseUrlLen,
                                const pipeline_u8 *fragment, pipeline_u32 fragmentLen,
                                pipeline_u8 *out, pipeline_u32 outCap)
{
    static const pipeline_u8 sep[] = PIPELINE_URL_FRAGMENT_SEP;
    pipeline_u32 total;
    pipeline_u32 pos;
    pipeline_u32 i;

    total = baseUrlLen + (pipeline_u32)PIPELINE_URL_FRAGMENT_SEP_LEN + fragmentLen;
    if (total > outCap) {
        return 0;
    }

    pos = 0;
    for (i = 0; i < baseUrlLen; i++) {
        out[pos] = baseUrl[i];
        pos++;
    }
    for (i = 0; i < (pipeline_u32)PIPELINE_URL_FRAGMENT_SEP_LEN; i++) {
        out[pos] = sep[i];
        pos++;
    }
    for (i = 0; i < fragmentLen; i++) {
        out[pos] = fragment[i];
        pos++;
    }
    return total;
}

int pipeline_url_extract_fragment(const pipeline_u8 *url, pipeline_u32 urlLen,
                                   pipeline_u8 *fragmentOut, pipeline_u32 outCap, pipeline_u32 *fragmentLenOut)
{
    pipeline_u8 sepByte = (pipeline_u8)PIPELINE_URL_FRAGMENT_SEP[0];
    pipeline_u32 sepPos;
    pipeline_u32 fragLen;
    pipeline_u32 i;

    sepPos = urlLen; /* "not found" sentinel */
    for (i = 0; i < urlLen; i++) {
        if (url[i] == sepByte) {
            sepPos = i;
            break;
        }
    }
    if (sepPos == urlLen) {
        return 0; /* no '#' anywhere in url -- host-agnostic, but a fragment must still exist */
    }

    fragLen = urlLen - sepPos - (pipeline_u32)PIPELINE_URL_FRAGMENT_SEP_LEN;
    if (fragLen > outCap) {
        return 0;
    }
    for (i = 0; i < fragLen; i++) {
        fragmentOut[i] = url[sepPos + (pipeline_u32)PIPELINE_URL_FRAGMENT_SEP_LEN + i];
    }
    *fragmentLenOut = fragLen;
    return 1;
}
