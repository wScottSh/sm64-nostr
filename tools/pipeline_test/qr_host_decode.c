/*
 * See qr_host_decode.h. Host-only: normal hosted C99 (real <stdint.h>/
 * <stdbool.h>/<string.h> are fine here, unlike src/pipeline/qrcodegen.c,
 * which is freestanding).
 *
 * The block-layout tables below (ECC_CODEWORDS_PER_BLOCK,
 * NUM_ERROR_CORRECTION_BLOCKS) and the getNumRawDataModules()/
 * getAlignmentPatternPositions() formulas are intentionally the same
 * structural constants qrcodegen.c uses internally (Project Nayuki's QR
 * Code generator library, MIT License) -- duplicated here, not shared,
 * because qrcodegen.c keeps them file-static (this port hides everything
 * except qrcodegen_encodeBinary/getSize/getModule -- see its own header
 * comment) and because a real-world QR reader (camera scan, companion app)
 * would equally have to know the QR Model 2 spec's own fixed tables, not
 * reach into this project's encoder internals. This is the "decode routine
 * driven by the same qrcodegen structural data" the sub-issue calls for.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "qr_adapter.h"
#include "qr_host_decode.h"

typedef uint8_t qhd_u8;

static const int8_t ECC_CODEWORDS_PER_BLOCK[4][41] = {
    {-1,  7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
    {-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28},
    {-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
    {-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
};

static const int8_t NUM_ERROR_CORRECTION_BLOCKS[4][41] = {
    {-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4,  4,  4,  4,  4,  6,  6,  6,  6,  7,  8,  8,  9,  9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25},
    {-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5,  5,  8,  9,  9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49},
    {-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8,  8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68},
    {-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81},
};

static int getNumRawDataModules(int ver)
{
    int result = (16 * ver + 128) * ver + 64;
    if (ver >= 2) {
        int numAlign = ver / 7 + 2;
        result -= (25 * numAlign - 10) * numAlign - 55;
        if (ver >= 7)
            result -= 36;
    }
    return result;
}

static int getAlignmentPatternPositions(int version, int result[7])
{
    if (version == 1)
        return 0;
    int numAlign = version / 7 + 2;
    int step = (version * 8 + numAlign * 3 + 5) / (numAlign * 4 - 4) * 2;
    int i, pos;
    for (i = numAlign - 1, pos = version * 4 + 10; i >= 1; i--, pos -= step)
        result[i] = pos;
    result[0] = 6;
    return numAlign;
}

#define QHD_MAX_SIZE PIPELINE_QR_MODULE_SIZE

static bool isFunctionModule[QHD_MAX_SIZE][QHD_MAX_SIZE];

static void markRect(int left, int top, int width, int height)
{
    int dy, dx;
    for (dy = 0; dy < height; dy++)
        for (dx = 0; dx < width; dx++)
            isFunctionModule[top + dy][left + dx] = true;
}

static void buildFunctionModuleMap(int version, int qrsize)
{
    int alignPatPos[7];
    int numAlign, i, j;

    memset(isFunctionModule, 0, sizeof(isFunctionModule));

    markRect(6, 0, 1, qrsize);   // Vertical timing pattern
    markRect(0, 6, qrsize, 1);   // Horizontal timing pattern

    markRect(0, 0, 9, 9);                 // Top-left finder + format
    markRect(qrsize - 8, 0, 8, 9);        // Top-right finder + format
    markRect(0, qrsize - 8, 9, 8);        // Bottom-left finder + format

    numAlign = getAlignmentPatternPositions(version, alignPatPos);
    for (i = 0; i < numAlign; i++) {
        for (j = 0; j < numAlign; j++) {
            if ((i == 0 && j == 0) || (i == 0 && j == numAlign - 1) || (i == numAlign - 1 && j == 0))
                continue;
            markRect(alignPatPos[i] - 2, alignPatPos[j] - 2, 5, 5);
        }
    }
    // No version-info blocks below version 7; PIPELINE_QR_VERSION (6) never needs them.
}

static bool maskInvert(enum qrcodegen_Mask mask, int x, int y)
{
    switch ((int)mask) {
        case 0: return (x + y) % 2 == 0;
        case 1: return y % 2 == 0;
        case 2: return x % 3 == 0;
        case 3: return (x + y) % 3 == 0;
        case 4: return (x / 3 + y / 2) % 2 == 0;
        case 5: return x * y % 2 + x * y % 3 == 0;
        case 6: return (x * y % 2 + x * y % 3) % 2 == 0;
        case 7: return ((x + y) % 2 + x * y % 3) % 2 == 0;
        default: return false;
    }
}

// Reads the first copy of the 15-bit format-info field (same positions
// qrcodegen.c's drawFormatBits() writes), recovering both the mask pattern
// (chosen dynamically by qrcodegen_Mask_AUTO at encode time -- this is a
// real decode of it, not an assumption) and the ECC level, which must
// match the fixed `expectedEcl` this decoder was built for. No BCH error
// correction is applied to the 15 bits (this decodes a bitmap this same
// process built in memory, never a noisy scan), so a mismatch here means
// the bitmap wasn't produced the way this decoder expects, not a corrupted
// scan -- returns 0 in that case rather than guessing.
static int readFormatBits(const unsigned char *qrcode, enum qrcodegen_Ecc expectedEcl, enum qrcodegen_Mask *maskOut)
{
    // ECC-level index -> format-bits value, and its self-inverse (mirrors
    // qrcodegen.c's drawFormatBits() `table`): LOW->1, MEDIUM->0,
    // QUARTILE->3, HIGH->2.
    static const int eclToFormatValue[4] = {1, 0, 3, 2};
    int bits = 0;
    int i;
    int coordX[15], coordY[15];
    int raw, data, mask, eclFormatValue;

    for (i = 0; i <= 5; i++) { coordX[i] = 8; coordY[i] = i; }
    coordX[6] = 8; coordY[6] = 7;
    coordX[7] = 8; coordY[7] = 8;
    coordX[8] = 7; coordY[8] = 8;
    for (i = 9; i < 15; i++) { coordX[i] = 14 - i; coordY[i] = 8; }

    for (i = 0; i < 15; i++) {
        int dark = pipeline_qr_get_module(qrcode, coordX[i], coordY[i]) ? 1 : 0;
        bits |= dark << i;
    }

    raw  = bits ^ 0x5412;
    data = raw >> 10;   // 5 bits: 2-bit ECC-level index, 3-bit mask
    mask = data & 0x7;
    eclFormatValue = data >> 3;

    if (eclFormatValue < 0 || eclFormatValue > 3 || eclToFormatValue[(int)expectedEcl] != eclFormatValue) {
        return 0;
    }
    *maskOut = (enum qrcodegen_Mask)mask;
    return 1;
}

// Mirrors qrcodegen.c's drawCodewords() zigzag scan, but reads (and
// mask-unapplies) bits instead of writing them.
static void readCodewordsZigzag(const unsigned char *qrcode, int qrsize, enum qrcodegen_Mask mask,
                                 qhd_u8 *codewords, int codewordCount)
{
    int i = 0;
    int right;

    memset(codewords, 0, (size_t)codewordCount);
    for (right = qrsize - 1; right >= 1; right -= 2) {
        if (right == 6)
            right = 5;
        int vert;
        for (vert = 0; vert < qrsize; vert++) {
            int j;
            for (j = 0; j < 2; j++) {
                int x = right - j;
                bool upward = ((right + 1) & 2) == 0;
                int y = upward ? qrsize - 1 - vert : vert;
                if (!isFunctionModule[y][x] && i < codewordCount * 8) {
                    bool dark = pipeline_qr_get_module(qrcode, x, y) ? true : false;
                    bool invert = maskInvert(mask, x, y);
                    bool bit = dark ^ invert;
                    codewords[i >> 3] |= (bit ? 1 : 0) << (7 - (i & 7));
                    i++;
                }
            }
        }
    }
}

static void deinterleave(const qhd_u8 *codewords, int rawCodewords, int numBlocks, int blockEccLen,
                          int dataCodewords, qhd_u8 *dataOut)
{
    int numShortBlocks = numBlocks - rawCodewords % numBlocks;
    int shortBlockDataLen = rawCodewords / numBlocks - blockEccLen;
    int i;
    int pos = 0;

    for (i = 0; i < numBlocks; i++) {
        int datLen = shortBlockDataLen + (i < numShortBlocks ? 0 : 1);
        int j, k;
        for (j = 0, k = i; j < datLen; j++, k += numBlocks) {
            if (j == shortBlockDataLen)
                k -= numShortBlocks;
            dataOut[pos + j] = codewords[k];
        }
        pos += datLen;
    }
    (void)dataCodewords;
}

int qr_host_decode(const unsigned char *qrcode, unsigned char *out, int outCap, int *outLen)
{
    int qrsize = pipeline_qr_get_size(qrcode);
    int version = PIPELINE_QR_VERSION;
    enum qrcodegen_Ecc ecl = PIPELINE_QR_ECC;
    int rawCodewords, dataCodewords, numBlocks, blockEccLen;
    enum qrcodegen_Mask mask;
    qhd_u8 codewords[qrcodegen_BUFFER_LEN_FOR_VERSION(PIPELINE_QR_VERSION)];
    qhd_u8 dataBytes[PIPELINE_QR_DATA_CODEWORDS];
    int bitPos, mode, numChars, i;

    if (qrsize != PIPELINE_QR_MODULE_SIZE) {
        return 0;
    }

    rawCodewords   = getNumRawDataModules(version) / 8;
    blockEccLen    = ECC_CODEWORDS_PER_BLOCK[(int)ecl][version];
    numBlocks      = NUM_ERROR_CORRECTION_BLOCKS[(int)ecl][version];
    dataCodewords  = rawCodewords - blockEccLen * numBlocks;

    if (dataCodewords > PIPELINE_QR_DATA_CODEWORDS) {
        return 0;
    }

    buildFunctionModuleMap(version, qrsize);
    if (!readFormatBits(qrcode, ecl, &mask)) {
        return 0;
    }
    readCodewordsZigzag(qrcode, qrsize, mask, codewords, rawCodewords);
    deinterleave(codewords, rawCodewords, numBlocks, blockEccLen, dataCodewords, dataBytes);

    // Parse the bitstream: 4-bit mode indicator, then an 8-bit byte-mode
    // character count (versions 1-9), then numChars data bytes -- exactly
    // what qrcodegen_encodeBinary() wrote via appendBitsToBuffer(). No
    // Reed-Solomon correction needed: dataBytes[] came from a bitmap this
    // same process built in memory, never a noisy scan.
    bitPos = 0;
    mode = (dataBytes[0] >> 4) & 0xF;
    if (mode != 0x4 /* qrcodegen_Mode_BYTE */) {
        return 0;
    }
    bitPos += 4;
    numChars = 0;
    for (i = 0; i < 8; i++) {
        int bit = (dataBytes[bitPos >> 3] >> (7 - (bitPos & 7))) & 1;
        numChars = (numChars << 1) | bit;
        bitPos++;
    }
    if (numChars > outCap || (bitPos + numChars * 8) > dataCodewords * 8) {
        return 0;
    }
    for (i = 0; i < numChars; i++) {
        int byteVal = 0;
        int b;
        for (b = 0; b < 8; b++) {
            int bit = (dataBytes[bitPos >> 3] >> (7 - (bitPos & 7))) & 1;
            byteVal = (byteVal << 1) | bit;
            bitPos++;
        }
        out[i] = (unsigned char)byteVal;
    }
    *outLen = numChars;
    return 1;
}
