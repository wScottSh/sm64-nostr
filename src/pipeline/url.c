/*
 * See url.h. Pure C89: no MarioState, no globals, no N64 headers, no C99
 * syntax.
 */

#include "url.h"

pipeline_u32 pipeline_url_wrap(const pipeline_u8 *baseUrl, pipeline_u32 baseUrlLen,
                                const pipeline_u8 *fragment, pipeline_u32 fragmentLen,
                                pipeline_u8 *out, pipeline_u32 outCap)
{
    static const pipeline_u8 scheme[] = PIPELINE_URL_SCHEME;
    static const pipeline_u8 sep[] = PIPELINE_URL_PATH_SEP;
    pipeline_u32 total;
    pipeline_u32 pos;
    pipeline_u32 i;

    total = (pipeline_u32)PIPELINE_URL_SCHEME_LEN + baseUrlLen +
            (pipeline_u32)PIPELINE_URL_PATH_SEP_LEN + fragmentLen;
    if (total > outCap) {
        return 0;
    }

    pos = 0;
    for (i = 0; i < (pipeline_u32)PIPELINE_URL_SCHEME_LEN; i++) {
        out[pos] = scheme[i];
        pos++;
    }
    for (i = 0; i < baseUrlLen; i++) {
        out[pos] = baseUrl[i];
        pos++;
    }
    for (i = 0; i < (pipeline_u32)PIPELINE_URL_PATH_SEP_LEN; i++) {
        out[pos] = sep[i];
        pos++;
    }
    for (i = 0; i < fragmentLen; i++) {
        out[pos] = fragment[i];
        pos++;
    }
    return total;
}

int pipeline_url_strip(const pipeline_u8 *url, pipeline_u32 urlLen,
                        const pipeline_u8 *baseUrl, pipeline_u32 baseUrlLen,
                        pipeline_u8 *fragmentOut, pipeline_u32 outCap, pipeline_u32 *fragmentLenOut)
{
    static const pipeline_u8 scheme[] = PIPELINE_URL_SCHEME;
    static const pipeline_u8 sep[] = PIPELINE_URL_PATH_SEP;
    pipeline_u32 prefixLen;
    pipeline_u32 fragLen;
    pipeline_u32 i;

    prefixLen = (pipeline_u32)PIPELINE_URL_SCHEME_LEN + baseUrlLen + (pipeline_u32)PIPELINE_URL_PATH_SEP_LEN;
    if (urlLen < prefixLen) {
        return 0;
    }
    for (i = 0; i < (pipeline_u32)PIPELINE_URL_SCHEME_LEN; i++) {
        if (url[i] != scheme[i]) {
            return 0;
        }
    }
    for (i = 0; i < baseUrlLen; i++) {
        if (url[(pipeline_u32)PIPELINE_URL_SCHEME_LEN + i] != baseUrl[i]) {
            return 0;
        }
    }
    for (i = 0; i < (pipeline_u32)PIPELINE_URL_PATH_SEP_LEN; i++) {
        if (url[(pipeline_u32)PIPELINE_URL_SCHEME_LEN + baseUrlLen + i] != sep[i]) {
            return 0;
        }
    }

    fragLen = urlLen - prefixLen;
    if (fragLen > outCap) {
        return 0;
    }
    for (i = 0; i < fragLen; i++) {
        fragmentOut[i] = url[prefixLen + i];
    }
    *fragmentLenOut = fragLen;
    return 1;
}
