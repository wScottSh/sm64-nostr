/*
 * See pack_adapter.h. Both functions write/read fields one byte at a time
 * at descriptor-derived offsets, never via memcpy/struct-layout, mirroring
 * the same explicit-serialization discipline build_event.h documents for
 * the eventual real serialize stage. Format v2 (spec #52, sub-issue #54)
 * added CREATED_AT/PUBKEY/TAG_LEN+TAG, all still one byte at a time. Format
 * v3 (spec #109, sub-issue #110) adds a second length-prefixed field,
 * NAME_LEN+NAME, mirroring TAG_LEN+TAG exactly; SIG's offset now depends on
 * BOTH runtime lengths, via the PIPELINE_FMT_OFF_SIG(tagLen, nameLen)
 * function-like macro format_descriptor.h generates.
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

pipeline_u32 pipeline_pack(const StarCapture *capture,
                            pipeline_u32 createdAt,
                            const pipeline_u8 pubkey[PIPELINE_FMT_SIZE_PUBKEY],
                            const pipeline_u8 *tag,
                            pipeline_u8 tagLen,
                            const pipeline_u8 *name,
                            pipeline_u8 nameLen,
                            const pipeline_u8 sig[PIPELINE_FMT_SIZE_SIG],
                            pipeline_u8 *out)
{
    pipeline_u32 i;
    pipeline_u32 nameLenOff;
    pipeline_u32 nameOff;
    pipeline_u32 sigOff;

    if (tagLen > PIPELINE_PACK_MAX_TAG_LEN) {
        return 0;
    }
    if (nameLen > PIPELINE_PACK_MAX_NAME_LEN) {
        return 0;
    }

    write_u8(out, PIPELINE_FMT_OFF_FORMAT_TAG, (pipeline_u8)PIPELINE_FMT_TAG_VALUE);
    write_u8(out, PIPELINE_FMT_OFF_COURSE, capture->course);
    write_u8(out, PIPELINE_FMT_OFF_ACT, capture->act);
    write_u8(out, PIPELINE_FMT_OFF_COINS, capture->coins);
    write_u32_be(out, PIPELINE_FMT_OFF_FRAMES, capture->frames);
    write_u16_be(out, PIPELINE_FMT_OFF_NONCE16, capture->nonce16);
    write_u8(out, PIPELINE_FMT_OFF_KEY_ID, capture->keyId);
    write_u32_be(out, PIPELINE_FMT_OFF_CREATED_AT, createdAt);

    for (i = 0; i < PIPELINE_FMT_SIZE_PUBKEY; i++) {
        out[PIPELINE_FMT_OFF_PUBKEY + i] = pubkey[i];
    }

    write_u8(out, PIPELINE_FMT_OFF_TAG_LEN, tagLen);
    for (i = 0; i < tagLen; i++) {
        out[PIPELINE_FMT_OFF_TAG + i] = tag[i];
    }

    nameLenOff = PIPELINE_FMT_OFF_NAME_LEN(tagLen);
    write_u8(out, nameLenOff, nameLen);
    nameOff = PIPELINE_FMT_OFF_NAME(tagLen);
    for (i = 0; i < nameLen; i++) {
        out[nameOff + i] = name[i];
    }

    sigOff = PIPELINE_FMT_OFF_SIG(tagLen, nameLen);
    for (i = 0; i < PIPELINE_FMT_SIZE_SIG; i++) {
        out[sigOff + i] = sig[i];
    }

    return PIPELINE_FMT_TOTAL_SIZE(tagLen, nameLen);
}

int pipeline_unpack(const pipeline_u8 *in,
                     pipeline_u32 inLen,
                     StarCapture *capture_out,
                     pipeline_u32 *createdAt_out,
                     pipeline_u8 pubkey_out[PIPELINE_FMT_SIZE_PUBKEY],
                     pipeline_u8 tag_out[PIPELINE_PACK_MAX_TAG_LEN],
                     pipeline_u8 *tagLen_out,
                     pipeline_u8 name_out[PIPELINE_PACK_MAX_NAME_LEN],
                     pipeline_u8 *nameLen_out,
                     pipeline_u8 sig_out[PIPELINE_FMT_SIZE_SIG])
{
    pipeline_u8 tagLen;
    pipeline_u8 nameLen;
    pipeline_u32 nameLenOff;
    pipeline_u32 nameOff;
    pipeline_u32 expectedLen;
    pipeline_u32 sigOff;
    pipeline_u32 i;

    /* At least one byte is needed to even inspect FORMAT_TAG. A payload
     * tagged with the old format v2 value (0x02) is rejected right here --
     * never silently misread as v3. */
    if (inLen < 1 || in[PIPELINE_FMT_OFF_FORMAT_TAG] != (pipeline_u8)PIPELINE_FMT_TAG_VALUE) {
        return PIPELINE_UNPACK_ERR_BAD_FORMAT_TAG;
    }

    /* PIPELINE_FMT_FIXED_SIZE is the minimum possible v3 payload (TAG_LEN ==
     * NAME_LEN == 0); anything shorter can't even hold a valid TAG_LEN,
     * NAME_LEN, and SIG, so it's safe to read in[PIPELINE_FMT_OFF_TAG_LEN]
     * once past this check. */
    if (inLen < PIPELINE_FMT_FIXED_SIZE) {
        return PIPELINE_UNPACK_ERR_WRONG_LENGTH;
    }

    tagLen = in[PIPELINE_FMT_OFF_TAG_LEN];
    if (tagLen > PIPELINE_PACK_MAX_TAG_LEN) {
        return PIPELINE_UNPACK_ERR_TAG_TOO_LONG;
    }

    /* NAME_LEN's own offset depends on tagLen (it comes right after TAG).
     * Reading it here is still safe even though inLen has only been checked
     * against PIPELINE_FMT_FIXED_SIZE (the zero-tagLen/zero-nameLen
     * minimum): PIPELINE_FMT_FIXED_SIZE already includes NAME_LEN's own
     * fixed byte plus the whole fixed SIG field after it, and SIG (64 B)
     * alone comfortably exceeds PIPELINE_PACK_MAX_TAG_LEN, so the wire
     * offset of NAME_LEN (OFF_TAG + tagLen, tagLen <= PIPELINE_PACK_MAX_TAG_LEN)
     * can never run past inLen once inLen >= PIPELINE_FMT_FIXED_SIZE. */
    nameLenOff = PIPELINE_FMT_OFF_NAME_LEN(tagLen);
    nameLen = in[nameLenOff];
    if (nameLen > PIPELINE_PACK_MAX_NAME_LEN) {
        return PIPELINE_UNPACK_ERR_NAME_TOO_LONG;
    }

    expectedLen = PIPELINE_FMT_TOTAL_SIZE(tagLen, nameLen);
    if (inLen != expectedLen) {
        return PIPELINE_UNPACK_ERR_WRONG_LENGTH;
    }

    capture_out->course  = in[PIPELINE_FMT_OFF_COURSE];
    capture_out->act     = in[PIPELINE_FMT_OFF_ACT];
    capture_out->coins   = in[PIPELINE_FMT_OFF_COINS];
    capture_out->frames  = read_u32_be(in, PIPELINE_FMT_OFF_FRAMES);
    capture_out->nonce16 = read_u16_be(in, PIPELINE_FMT_OFF_NONCE16);
    capture_out->keyId   = in[PIPELINE_FMT_OFF_KEY_ID];

    *createdAt_out = read_u32_be(in, PIPELINE_FMT_OFF_CREATED_AT);

    for (i = 0; i < PIPELINE_FMT_SIZE_PUBKEY; i++) {
        pubkey_out[i] = in[PIPELINE_FMT_OFF_PUBKEY + i];
    }

    for (i = 0; i < tagLen; i++) {
        tag_out[i] = in[PIPELINE_FMT_OFF_TAG + i];
    }
    *tagLen_out = tagLen;

    nameOff = PIPELINE_FMT_OFF_NAME(tagLen);
    for (i = 0; i < nameLen; i++) {
        name_out[i] = in[nameOff + i];
    }
    *nameLen_out = nameLen;

    sigOff = PIPELINE_FMT_OFF_SIG(tagLen, nameLen);
    for (i = 0; i < PIPELINE_FMT_SIZE_SIG; i++) {
        sig_out[i] = in[sigOff + i];
    }

    return PIPELINE_UNPACK_OK;
}
