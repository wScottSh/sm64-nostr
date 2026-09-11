/*
 * See qr_adapter.h. Pure C89: no MarioState, no globals, no N64 headers,
 * no C99 syntax (unlike qrcodegen.c itself, which is the ported C99 TU
 * this file calls into).
 */

#include "qr_adapter.h"

int pipeline_qr_encode(const pipeline_u8 *payload, pipeline_u32 payloadLen,
                        pipeline_u8 out[PIPELINE_QR_BUFFER_LEN])
{
    qr_u8 dataAndTemp[PIPELINE_QR_BUFFER_LEN];
    pipeline_u32 i;

    /*
     * The real, documented over-budget boundary: PIPELINE_QR_MAX_PAYLOAD_BYTES
     * (122, far below dataAndTemp's declared size) is also what
     * qrcodegen_encodeBinary()'s own version-fit search below would reject
     * on its own -- but checking it explicitly here, rather than leaving it
     * as an emergent property of the version/ECC constants below, means
     * this seam's documented contract (qr_adapter.h) can never silently
     * drift out of sync with its enforcement if those constants ever
     * change.
     */
    if (payloadLen > (pipeline_u32)PIPELINE_QR_MAX_PAYLOAD_BYTES) {
        out[0] = 0; /* invalid-size sentinel, matching qrcodegen_encodeBinary's own rejection path */
        return 0;
    }

    /*
     * Safety net ahead of the copy loop below: dataAndTemp is a fixed-size
     * stack buffer, so payloadLen must never exceed its length regardless
     * of the check above. This can only trip if PIPELINE_QR_MAX_PAYLOAD_BYTES
     * itself were ever misconfigured larger than the buffer -- belt and
     * braces, not the primary rejection path.
     */
    if (payloadLen > (pipeline_u32)(PIPELINE_QR_BUFFER_LEN - 1)) {
        out[0] = 0;
        return 0;
    }

    for (i = 0; i < payloadLen; i++) {
        dataAndTemp[i] = payload[i];
    }

    return qrcodegen_encodeBinary(dataAndTemp, (int)payloadLen, out,
                                   PIPELINE_QR_ECC, PIPELINE_QR_VERSION, PIPELINE_QR_VERSION,
                                   PIPELINE_QR_MASK, 0);
}

int pipeline_qr_encode_alphanumeric(const pipeline_u8 *text, pipeline_u32 textLen,
                                     pipeline_u8 out[PIPELINE_QR_BUFFER_LEN])
{
    qr_u8 tempBuffer[PIPELINE_QR_BUFFER_LEN];

    /*
     * The real, documented over-budget boundary, checked explicitly here
     * for the same reason pipeline_qr_encode() checks
     * PIPELINE_QR_MAX_PAYLOAD_BYTES explicitly above: so this seam's
     * documented contract (qr_adapter.h) can never silently drift out of
     * sync with its enforcement even though qrcodegen_encodeAlphanumeric()
     * would also reject an over-budget call on its own.
     */
    if (textLen > (pipeline_u32)PIPELINE_QR_ALNUM_MAX_CHARS) {
        out[0] = 0;
        return 0;
    }

    return qrcodegen_encodeAlphanumeric(text, (int)textLen, out, tempBuffer,
                                         PIPELINE_QR_ECC, PIPELINE_QR_VERSION, PIPELINE_QR_VERSION,
                                         PIPELINE_QR_MASK, 0);
}

int pipeline_qr_encode_two_segment(const pipeline_u8 *byteData, pipeline_u32 byteLen,
                                    const pipeline_u8 *alnumText, pipeline_u32 alnumLen,
                                    pipeline_u8 out[PIPELINE_QR_BUFFER_LEN])
{
    qr_u8 tempBuffer[PIPELINE_QR_BUFFER_LEN];

    return qrcodegen_encodeTwoSegments(byteData, (int)byteLen, alnumText, (int)alnumLen, out, tempBuffer,
                                        PIPELINE_QR_ECC, PIPELINE_QR_VERSION, PIPELINE_QR_VERSION,
                                        PIPELINE_QR_MASK, 0);
}

int pipeline_qr_get_size(const pipeline_u8 qrcode[PIPELINE_QR_BUFFER_LEN])
{
    return qrcodegen_getSize(qrcode);
}

int pipeline_qr_get_module(const pipeline_u8 qrcode[PIPELINE_QR_BUFFER_LEN], int x, int y)
{
    return qrcodegen_getModule(qrcode, x, y);
}
