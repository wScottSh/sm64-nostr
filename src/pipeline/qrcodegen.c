/*
 * Internal C99 port (spec #24, sub-issue #27) of a byte-mode-only subset of
 * Project Nayuki's QR Code generator library (C):
 *   https://github.com/nayuki/QR-Code-generator (c/qrcodegen.c)
 *
 * Copyright (c) Project Nayuki. (MIT License)
 * https://www.nayuki.io/page/qr-code-generator-library
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * - The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 * - The Software is provided "as is", without warranty of any kind, express or
 *   implied, including but not limited to the warranties of merchantability,
 *   fitness for a particular purpose and noninfringement. In no event shall the
 *   authors or copyright holders be liable for any claim, damages or other
 *   liability, whether in an action of contract, tort or otherwise, arising from,
 *   out of or in connection with the Software or the use or other dealings in the
 *   Software.
 *
 * See qrcodegen.h for what "port, not vendor drop" means here and why. In
 * short: two kinds of change from upstream, both mechanical --
 *
 * 1. No standard headers. The ROM build compiles under -nostdinc/
 *    -ffreestanding, so <assert.h>/<stdbool.h>/<stddef.h>/<stdint.h>/
 *    <stdlib.h>/<string.h> are all unavailable (see build_event.h's own
 *    note on <stdint.h>). This file supplies local equivalents just below:
 *    qr_u8 for uint8_t, plain `int` for bool/true/false (1/0), `signed
 *    char` for int8_t, and hand-rolled qr_memset/qr_memcpy/qr_memmove/
 *    qr_abs/qr_labs standing in for the libc functions of the same name.
 *    assert() becomes a no-op (see the comment on the macro below) rather
 *    than pulling in a freestanding-safe assert facility that doesn't
 *    exist yet in this codebase.
 *
 * 2. Byte-mode-only, no free text API. Upstream's numeric/alphanumeric/
 *    kanji/ECI segment factories, qrcodegen_isNumeric/isAlphanumeric,
 *    qrcodegen_encodeText, and qrcodegen_calcSegmentBufferSize are all
 *    dropped -- the pipeline only ever encodes an already-serialized byte
 *    buffer (never free-form text), so keeping that unused surface around
 *    would be exactly the kind of unhidden, unexercised API this repo's
 *    "internal ports are hidden behind the pipeline interface" rule (spec
 *    #24 story 21) exists to avoid. Every remaining function below is
 *    plain `static` except the three declared in qrcodegen.h, so nothing
 *    outside this file can reach the algorithm's internals directly.
 *
 * Everything else -- the bit buffer, Reed-Solomon ECC generation, function
 * pattern drawing, zigzag codeword placement, masking, and penalty-based
 * automatic mask selection -- is unchanged from upstream: those stages
 * don't care what mode produced the data bits, so there was no reason to
 * touch them beyond the type/library substitutions above.
 */

#include "qrcodegen.h"

/*---- Freestanding-safe local replacements for libc facilities ----*/

/* assert() here only guards internal algorithmic invariants (never input
 * validation -- qrcodegen_encodeBinary() reports over-capacity input via
 * its own return value, not assert), so making it a no-op changes no
 * observable behavior; this mirrors building the upstream library with
 * NDEBUG defined. */
#define assert(x) ((void)0)

#define LONG_MAX_SENTINEL 0x7FFFFFFFL

static void qr_memset(qr_u8 *dst, int value, int count)
{
    int i;
    for (i = 0; i < count; i++) {
        dst[i] = (qr_u8)value;
    }
}

static void qr_memcpy(qr_u8 *dst, const qr_u8 *src, int count)
{
    int i;
    for (i = 0; i < count; i++) {
        dst[i] = src[i];
    }
}

static void qr_memmove(qr_u8 *dst, const qr_u8 *src, int count)
{
    int i;
    if (dst < src) {
        for (i = 0; i < count; i++) {
            dst[i] = src[i];
        }
    } else {
        for (i = count; i > 0; i--) {
            dst[i - 1] = src[i - 1];
        }
    }
}

static int qr_abs(int x)
{
    return x < 0 ? -x : x;
}

static long qr_labs(long x)
{
    return x < 0 ? -x : x;
}


/*---- Private types (only BYTE and ALPHANUMERIC qrcodegen_Mode values are ever produced) ----*/

enum qrcodegen_Mode {
    qrcodegen_Mode_ALPHANUMERIC = 0x2,
    qrcodegen_Mode_BYTE         = 0x4
};

struct qrcodegen_Segment {
    enum qrcodegen_Mode mode;
    int numChars;
    qr_u8 *data;
    int bitLength;
};


/*---- Forward declarations for private functions ----*/

static void appendBitsToBuffer(unsigned int val, int numBits, qr_u8 buffer[], int *bitLen);

static int qrcodegen_encodeSegmentsAdvanced(const struct qrcodegen_Segment segs[], int len, enum qrcodegen_Ecc ecl,
    int minVersion, int maxVersion, enum qrcodegen_Mask mask, int boostEcl, qr_u8 tempBuffer[], qr_u8 qrcode[]);

// Shared tail of segment encoding (spec #115, sub-issue #116): terminator/padding,
// ECC generation + interleaving, function-module drawing, and masking -- the part
// that doesn't care which mode(s) produced the data bits already written into
// qrcode[0 : bitLen]. Factored out of qrcodegen_encodeSegmentsAdvanced() (still its
// only pre-existing caller, via qrcodegen_encodeBinary()) so qrcodegen_encodeAlphanumeric()
// can reuse it instead of duplicating this stage.
static int finishEncoding(qr_u8 qrcode[], int bitLen, int version, enum qrcodegen_Ecc ecl,
    enum qrcodegen_Mask mask, int boostEcl, qr_u8 tempBuffer[]);

static void addEccAndInterleave(qr_u8 data[], int version, enum qrcodegen_Ecc ecl, qr_u8 result[]);
static int getNumDataCodewords(int version, enum qrcodegen_Ecc ecl);
static int getNumRawDataModules(int ver);

static void reedSolomonComputeDivisor(int degree, qr_u8 result[]);
static void reedSolomonComputeRemainder(const qr_u8 data[], int dataLen,
    const qr_u8 generator[], int degree, qr_u8 result[]);
static qr_u8 reedSolomonMultiply(qr_u8 x, qr_u8 y);

static void initializeFunctionModules(int version, qr_u8 qrcode[]);
static void drawLightFunctionModules(qr_u8 qrcode[], int version);
static void drawFormatBits(enum qrcodegen_Ecc ecl, enum qrcodegen_Mask mask, qr_u8 qrcode[]);
static int getAlignmentPatternPositions(int version, qr_u8 result[7]);
static void fillRectangle(int left, int top, int width, int height, qr_u8 qrcode[]);

static void drawCodewords(const qr_u8 data[], int dataLen, qr_u8 qrcode[]);
static void applyMask(const qr_u8 functionModules[], qr_u8 qrcode[], enum qrcodegen_Mask mask);
static long getPenaltyScore(const qr_u8 qrcode[]);
static int finderPenaltyCountPatterns(const int runHistory[7], int qrsize);
static int finderPenaltyTerminateAndCount(int currentRunColor, int currentRunLength, int runHistory[7], int qrsize);
static void finderPenaltyAddHistory(int currentRunLength, int runHistory[7], int qrsize);

static int getModuleBounded(const qr_u8 qrcode[], int x, int y);
static void setModuleBounded(qr_u8 qrcode[], int x, int y, int isDark);
static void setModuleUnbounded(qr_u8 qrcode[], int x, int y, int isDark);
static int getBit(int x, int i);

static int calcSegmentBitLength(enum qrcodegen_Mode mode, int numChars);
static int getTotalBits(const struct qrcodegen_Segment segs[], int len, int version);
static int numCharCountBits(enum qrcodegen_Mode mode, int version);


/*---- Private tables of constants ----*/

#define LENGTH_OVERFLOW -1

// For generating error correction codes.
static const signed char ECC_CODEWORDS_PER_BLOCK[4][41] = {
    // Version: (note that index 0 is for padding, and is set to an illegal value)
    //0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40    Error correction level
    {-1,  7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},  // Low
    {-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28},  // Medium
    {-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},  // Quartile
    {-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},  // High
};

#define qrcodegen_REED_SOLOMON_DEGREE_MAX 30  // Based on the table above

// For generating error correction codes.
static const signed char NUM_ERROR_CORRECTION_BLOCKS[4][41] = {
    // Version: (note that index 0 is for padding, and is set to an illegal value)
    //0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40    Error correction level
    {-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4,  4,  4,  4,  4,  6,  6,  6,  6,  7,  8,  8,  9,  9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25},  // Low
    {-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5,  5,  8,  9,  9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49},  // Medium
    {-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8,  8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68},  // Quartile
    {-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81},  // High
};

// For automatic mask pattern selection.
static const int PENALTY_N1 =  3;
static const int PENALTY_N2 =  3;
static const int PENALTY_N3 = 40;
static const int PENALTY_N4 = 10;



/*---- High-level QR Code encoding function (byte mode only) ----*/

// Public function - see documentation comment in header file.
int qrcodegen_encodeBinary(qr_u8 dataAndTemp[], int dataLen, qr_u8 qrcode[],
        enum qrcodegen_Ecc ecl, int minVersion, int maxVersion, enum qrcodegen_Mask mask, int boostEcl) {

    struct qrcodegen_Segment seg;
    seg.mode = qrcodegen_Mode_BYTE;
    seg.bitLength = calcSegmentBitLength(seg.mode, dataLen);
    if (seg.bitLength == LENGTH_OVERFLOW) {
        qrcode[0] = 0;  // Set size to invalid value for safety
        return 0;
    }
    seg.numChars = dataLen;
    seg.data = dataAndTemp;
    return qrcodegen_encodeSegmentsAdvanced(&seg, 1, ecl, minVersion, maxVersion, mask, boostEcl, dataAndTemp, qrcode);
}


// Appends the given number of low-order bits of the given value to the given byte-based
// bit buffer, increasing the bit length. Requires 0 <= numBits <= 16 and val < 2^numBits.
static void appendBitsToBuffer(unsigned int val, int numBits, qr_u8 buffer[], int *bitLen) {
    assert(0 <= numBits && numBits <= 16 && (unsigned long)val >> numBits == 0);
    int i;
    for (i = numBits - 1; i >= 0; i--, (*bitLen)++)
        buffer[*bitLen >> 3] |= ((val >> i) & 1) << (7 - (*bitLen & 7));
}



/*---- Low-level QR Code encoding function (kept private: qrcodegen_encodeBinary is the only entry point) ----*/

static int qrcodegen_encodeSegmentsAdvanced(const struct qrcodegen_Segment segs[], int len, enum qrcodegen_Ecc ecl,
        int minVersion, int maxVersion, enum qrcodegen_Mask mask, int boostEcl, qr_u8 tempBuffer[], qr_u8 qrcode[]) {
    assert(segs != 0 || len == 0);
    assert(qrcodegen_VERSION_MIN <= minVersion && minVersion <= maxVersion && maxVersion <= qrcodegen_VERSION_MAX);
    assert(0 <= (int)ecl && (int)ecl <= 3 && -1 <= (int)mask && (int)mask <= 7);

    // Find the minimal version number to use
    int version, dataUsedBits;
    for (version = minVersion; ; version++) {
        int dataCapacityBits = getNumDataCodewords(version, ecl) * 8;  // Number of data bits available
        dataUsedBits = getTotalBits(segs, len, version);
        if (dataUsedBits != LENGTH_OVERFLOW && dataUsedBits <= dataCapacityBits)
            break;  // This version number is found to be suitable
        if (version >= maxVersion) {  // All versions in the range could not fit the given data
            qrcode[0] = 0;  // Set size to invalid value for safety
            return 0;
        }
    }
    assert(dataUsedBits != LENGTH_OVERFLOW);

    // Concatenate all segments to create the data bit string
    qr_memset(qrcode, 0, qrcodegen_BUFFER_LEN_FOR_VERSION(version));
    int bitLen = 0;
    int segIdx;
    for (segIdx = 0; segIdx < len; segIdx++) {
        const struct qrcodegen_Segment *seg = &segs[segIdx];
        appendBitsToBuffer((unsigned int)seg->mode, 4, qrcode, &bitLen);
        appendBitsToBuffer((unsigned int)seg->numChars, numCharCountBits(seg->mode, version), qrcode, &bitLen);
        int j;
        for (j = 0; j < seg->bitLength; j += 8) {
            int remaining = seg->bitLength - j;
            if (remaining >= 8) {
                appendBitsToBuffer((unsigned int)seg->data[j >> 3], 8, qrcode, &bitLen);
            } else {
                // Byte-mode segments are always a whole number of bytes, so this path is
                // unreachable in practice; kept only for structural fidelity with a
                // general-purpose bit buffer append.
                int bit = (seg->data[j >> 3] >> (7 - (j & 7))) & 1;
                appendBitsToBuffer((unsigned int)bit, 1, qrcode, &bitLen);
            }
        }
    }
    assert(bitLen == dataUsedBits);

    return finishEncoding(qrcode, bitLen, version, ecl, mask, boostEcl, tempBuffer);
}


// See the forward declaration's own comment above.
static int finishEncoding(qr_u8 qrcode[], int bitLen, int version, enum qrcodegen_Ecc ecl,
        enum qrcodegen_Mask mask, int boostEcl, qr_u8 tempBuffer[]) {
    // Increase the error correction level while the data still fits in the current version number
    int i;
    for (i = (int)qrcodegen_Ecc_MEDIUM; i <= (int)qrcodegen_Ecc_HIGH; i++) {  // From low to high
        if (boostEcl && bitLen <= getNumDataCodewords(version, (enum qrcodegen_Ecc)i) * 8)
            ecl = (enum qrcodegen_Ecc)i;
    }

    // Add terminator and pad up to a byte if applicable
    int dataCapacityBits = getNumDataCodewords(version, ecl) * 8;
    assert(bitLen <= dataCapacityBits);
    int terminatorBits = dataCapacityBits - bitLen;
    if (terminatorBits > 4)
        terminatorBits = 4;
    appendBitsToBuffer(0, terminatorBits, qrcode, &bitLen);
    appendBitsToBuffer(0, (8 - bitLen % 8) % 8, qrcode, &bitLen);
    assert(bitLen % 8 == 0);

    // Pad with alternating bytes until data capacity is reached
    qr_u8 padByte;
    for (padByte = 0xEC; bitLen < dataCapacityBits; padByte ^= 0xEC ^ 0x11)
        appendBitsToBuffer(padByte, 8, qrcode, &bitLen);

    // Compute ECC, draw modules
    addEccAndInterleave(qrcode, version, ecl, tempBuffer);
    initializeFunctionModules(version, qrcode);
    drawCodewords(tempBuffer, getNumRawDataModules(version) / 8, qrcode);
    drawLightFunctionModules(qrcode, version);
    initializeFunctionModules(version, tempBuffer);

    // Do masking
    if (mask == qrcodegen_Mask_AUTO) {  // Automatically choose best mask
        long minPenalty = LONG_MAX_SENTINEL;
        int m;
        for (m = 0; m < 8; m++) {
            enum qrcodegen_Mask msk = (enum qrcodegen_Mask)m;
            applyMask(tempBuffer, qrcode, msk);
            drawFormatBits(ecl, msk, qrcode);
            long penalty = getPenaltyScore(qrcode);
            if (penalty < minPenalty) {
                mask = msk;
                minPenalty = penalty;
            }
            applyMask(tempBuffer, qrcode, msk);  // Undoes the mask due to XOR
        }
    }
    assert(0 <= (int)mask && (int)mask <= 7);
    applyMask(tempBuffer, qrcode, mask);  // Apply the final choice of mask
    drawFormatBits(ecl, mask, qrcode);  // Overwrite old format bits
    return 1;
}


// QR Model 2's fixed 45-character alphanumeric charset (spec #115, sub-issue
// #116), in encoding order (index 0-44) -- the QR spec's own table, not a
// project secret, so duplicating it here (rather than exposing it publicly)
// is the same "hide the ported library, keep only the two narrow entry
// points" discipline this file's header comment already documents.
static const char ALPHANUMERIC_CHARSET[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
#define ALPHANUMERIC_CHARSET_LEN 45

// Returns the charset index (0-44) of c, or -1 if c is outside the QR
// alphanumeric charset.
static int alphanumericCharValue(qr_u8 c) {
    int i;
    for (i = 0; i < ALPHANUMERIC_CHARSET_LEN; i++) {
        if ((qr_u8)ALPHANUMERIC_CHARSET[i] == c)
            return i;
    }
    return -1;
}

// Returns the bit width of the character count field for an ALPHANUMERIC
// segment at the given version number (9/11/13 bits for versions 1-9/
// 10-26/27-40 -- the QR spec's own table, distinct from BYTE mode's
// 8/16/16 that numCharCountBits() above hardcodes).
static int alphanumericCharCountBits(int version) {
    assert(qrcodegen_VERSION_MIN <= version && version <= qrcodegen_VERSION_MAX);
    int i = (version + 7) / 17;
    static const int temp[] = { 9, 11, 13 };
    return temp[i];
}


/*---- High-level QR Code encoding function (alphanumeric mode) ----*/

// Public function - see documentation comment in header file.
int qrcodegen_encodeAlphanumeric(const qr_u8 text[], int textLen, qr_u8 qrcode[], qr_u8 tempBuffer[],
        enum qrcodegen_Ecc ecl, int minVersion, int maxVersion, enum qrcodegen_Mask mask, int boostEcl) {
    assert(qrcodegen_VERSION_MIN <= minVersion && minVersion <= maxVersion && maxVersion <= qrcodegen_VERSION_MAX);
    assert(0 <= (int)ecl && (int)ecl <= 3 && -1 <= (int)mask && (int)mask <= 7);

    if (textLen < 0 || textLen > 32767) {
        qrcode[0] = 0;
        return 0;
    }
    int i;
    for (i = 0; i < textLen; i++) {
        if (alphanumericCharValue(text[i]) < 0) {
            qrcode[0] = 0;  // Rejects non-alphanumeric-charset input, never silently drops/replaces it
            return 0;
        }
    }

    long bitLength = 11L * (textLen / 2) + (textLen % 2 != 0 ? 6 : 0);
    assert(bitLength <= 32767L);

    // Find the minimal version number to use (mirrors qrcodegen_encodeSegmentsAdvanced's own search)
    int version, ccbits;
    long totalBits;
    for (version = minVersion; ; version++) {
        int dataCapacityBits = getNumDataCodewords(version, ecl) * 8;
        ccbits = alphanumericCharCountBits(version);
        if (textLen < (1L << ccbits)) {
            totalBits = 4L + ccbits + bitLength;
            if (totalBits <= dataCapacityBits)
                break;  // This version number is found to be suitable
        }
        if (version >= maxVersion) {  // All versions in the range could not fit the given data
            qrcode[0] = 0;
            return 0;
        }
    }

    // Pack the mode indicator, character count, and alphanumeric-packed data bits
    qr_memset(qrcode, 0, qrcodegen_BUFFER_LEN_FOR_VERSION(version));
    int bitLen = 0;
    appendBitsToBuffer((unsigned int)qrcodegen_Mode_ALPHANUMERIC, 4, qrcode, &bitLen);
    appendBitsToBuffer((unsigned int)textLen, ccbits, qrcode, &bitLen);
    for (i = 0; i + 1 < textLen; i += 2) {
        int v = alphanumericCharValue(text[i]) * ALPHANUMERIC_CHARSET_LEN + alphanumericCharValue(text[i + 1]);
        appendBitsToBuffer((unsigned int)v, 11, qrcode, &bitLen);
    }
    if (textLen % 2 != 0) {
        appendBitsToBuffer((unsigned int)alphanumericCharValue(text[textLen - 1]), 6, qrcode, &bitLen);
    }
    assert((long)bitLen == 4L + ccbits + bitLength);

    return finishEncoding(qrcode, bitLen, version, ecl, mask, boostEcl, tempBuffer);
}


/*---- High-level QR Code encoding function (two segments: byte then alphanumeric) ----*/

// Public function - see documentation comment in header file.
int qrcodegen_encodeTwoSegments(const qr_u8 byteData[], int byteLen, const qr_u8 alnumText[], int alnumLen,
        qr_u8 qrcode[], qr_u8 tempBuffer[],
        enum qrcodegen_Ecc ecl, int minVersion, int maxVersion, enum qrcodegen_Mask mask, int boostEcl) {
    assert(qrcodegen_VERSION_MIN <= minVersion && minVersion <= maxVersion && maxVersion <= qrcodegen_VERSION_MAX);
    assert(0 <= (int)ecl && (int)ecl <= 3 && -1 <= (int)mask && (int)mask <= 7);

    if (byteLen < 0 || byteLen > 32767 || alnumLen < 0 || alnumLen > 32767) {
        qrcode[0] = 0;
        return 0;
    }
    int i;
    for (i = 0; i < alnumLen; i++) {
        if (alphanumericCharValue(alnumText[i]) < 0) {
            qrcode[0] = 0;  // Rejects non-alphanumeric-charset input, never silently drops/replaces it
            return 0;
        }
    }

    long byteBitLength = (long)byteLen * 8L;
    long alnumBitLength = 11L * (alnumLen / 2) + (alnumLen % 2 != 0 ? 6 : 0);
    if (byteBitLength > 32767L || alnumBitLength > 32767L) {
        qrcode[0] = 0;
        return 0;
    }

    // Find the minimal version number to use that fits BOTH segments (mirrors
    // qrcodegen_encodeSegmentsAdvanced()/qrcodegen_encodeAlphanumeric()'s own search).
    int version, byteCcbits, alnumCcbits;
    long totalBits;
    for (version = minVersion; ; version++) {
        int dataCapacityBits = getNumDataCodewords(version, ecl) * 8;
        byteCcbits = numCharCountBits(qrcodegen_Mode_BYTE, version);
        alnumCcbits = alphanumericCharCountBits(version);
        if (byteLen < (1L << byteCcbits) && alnumLen < (1L << alnumCcbits)) {
            totalBits = 4L + byteCcbits + byteBitLength + 4L + alnumCcbits + alnumBitLength;
            if (totalBits <= dataCapacityBits)
                break;  // This version number is found to be suitable
        }
        if (version >= maxVersion) {  // All versions in the range could not fit the given data
            qrcode[0] = 0;
            return 0;
        }
    }

    // Pack segment 1 (BYTE): mode indicator, character count, then data bytes
    qr_memset(qrcode, 0, qrcodegen_BUFFER_LEN_FOR_VERSION(version));
    int bitLen = 0;
    appendBitsToBuffer((unsigned int)qrcodegen_Mode_BYTE, 4, qrcode, &bitLen);
    appendBitsToBuffer((unsigned int)byteLen, byteCcbits, qrcode, &bitLen);
    for (i = 0; i < byteLen; i++) {
        appendBitsToBuffer((unsigned int)byteData[i], 8, qrcode, &bitLen);
    }

    // Pack segment 2 (ALPHANUMERIC): mode indicator, character count, then packed data
    appendBitsToBuffer((unsigned int)qrcodegen_Mode_ALPHANUMERIC, 4, qrcode, &bitLen);
    appendBitsToBuffer((unsigned int)alnumLen, alnumCcbits, qrcode, &bitLen);
    for (i = 0; i + 1 < alnumLen; i += 2) {
        int v = alphanumericCharValue(alnumText[i]) * ALPHANUMERIC_CHARSET_LEN + alphanumericCharValue(alnumText[i + 1]);
        appendBitsToBuffer((unsigned int)v, 11, qrcode, &bitLen);
    }
    if (alnumLen % 2 != 0) {
        appendBitsToBuffer((unsigned int)alphanumericCharValue(alnumText[alnumLen - 1]), 6, qrcode, &bitLen);
    }
    assert((long)bitLen == totalBits);

    return finishEncoding(qrcode, bitLen, version, ecl, mask, boostEcl, tempBuffer);
}



/*---- Error correction code generation functions ----*/

// Appends error correction bytes to each block of the given data array, then interleaves
// bytes from the blocks and stores them in the result array. data[0 : dataLen] contains
// the input data. data[dataLen : rawCodewords] is used as a temporary work area and will
// be clobbered by this function. The final answer is stored in result[0 : rawCodewords].
static void addEccAndInterleave(qr_u8 data[], int version, enum qrcodegen_Ecc ecl, qr_u8 result[]) {
    // Calculate parameter numbers
    assert(0 <= (int)ecl && (int)ecl < 4 && qrcodegen_VERSION_MIN <= version && version <= qrcodegen_VERSION_MAX);
    int numBlocks = NUM_ERROR_CORRECTION_BLOCKS[(int)ecl][version];
    int blockEccLen = ECC_CODEWORDS_PER_BLOCK  [(int)ecl][version];
    int rawCodewords = getNumRawDataModules(version) / 8;
    int dataLen = getNumDataCodewords(version, ecl);
    int numShortBlocks = numBlocks - rawCodewords % numBlocks;
    int shortBlockDataLen = rawCodewords / numBlocks - blockEccLen;

    // Split data into blocks, calculate ECC, and interleave
    // (not concatenate) the bytes into a single sequence
    qr_u8 rsdiv[qrcodegen_REED_SOLOMON_DEGREE_MAX];
    reedSolomonComputeDivisor(blockEccLen, rsdiv);
    const qr_u8 *dat = data;
    int i;
    for (i = 0; i < numBlocks; i++) {
        int datLen = shortBlockDataLen + (i < numShortBlocks ? 0 : 1);
        qr_u8 *ecc = &data[dataLen];  // Temporary storage
        reedSolomonComputeRemainder(dat, datLen, rsdiv, blockEccLen, ecc);
        int j, k;
        for (j = 0, k = i; j < datLen; j++, k += numBlocks) {  // Copy data
            if (j == shortBlockDataLen)
                k -= numShortBlocks;
            result[k] = dat[j];
        }
        for (j = 0, k = dataLen + i; j < blockEccLen; j++, k += numBlocks)  // Copy ECC
            result[k] = ecc[j];
        dat += datLen;
    }
}


// Returns the number of 8-bit codewords that can be used for storing data (not ECC),
// for the given version number and error correction level. The result is in the range [9, 2956].
static int getNumDataCodewords(int version, enum qrcodegen_Ecc ecl) {
    int v = version, e = (int)ecl;
    assert(0 <= e && e < 4);
    return getNumRawDataModules(v) / 8
        - ECC_CODEWORDS_PER_BLOCK    [e][v]
        * NUM_ERROR_CORRECTION_BLOCKS[e][v];
}


// Returns the number of data bits that can be stored in a QR Code of the given version number, after
// all function modules are excluded. This includes remainder bits, so it might not be a multiple of 8.
// The result is in the range [208, 29648]. This could be implemented as a 40-entry lookup table.
static int getNumRawDataModules(int ver) {
    assert(qrcodegen_VERSION_MIN <= ver && ver <= qrcodegen_VERSION_MAX);
    int result = (16 * ver + 128) * ver + 64;
    if (ver >= 2) {
        int numAlign = ver / 7 + 2;
        result -= (25 * numAlign - 10) * numAlign - 55;
        if (ver >= 7)
            result -= 36;
    }
    assert(208 <= result && result <= 29648);
    return result;
}



/*---- Reed-Solomon ECC generator functions ----*/

// Computes a Reed-Solomon ECC generator polynomial for the given degree, storing in result[0 : degree].
static void reedSolomonComputeDivisor(int degree, qr_u8 result[]) {
    assert(1 <= degree && degree <= qrcodegen_REED_SOLOMON_DEGREE_MAX);
    // Polynomial coefficients are stored from highest to lowest power, excluding the leading term which is always 1.
    qr_memset(result, 0, degree);
    result[degree - 1] = 1;  // Start off with the monomial x^0

    // Compute the product polynomial (x - r^0) * (x - r^1) * (x - r^2) * ... * (x - r^{degree-1}),
    // drop the highest monomial term which is always 1x^degree.
    // Note that r = 0x02, which is a generator element of this field GF(2^8/0x11D).
    qr_u8 root = 1;
    int i;
    for (i = 0; i < degree; i++) {
        // Multiply the current product by (x - r^i)
        int j;
        for (j = 0; j < degree; j++) {
            result[j] = reedSolomonMultiply(result[j], root);
            if (j + 1 < degree)
                result[j] ^= result[j + 1];
        }
        root = reedSolomonMultiply(root, 0x02);
    }
}


// Computes the Reed-Solomon error correction codeword for the given data and divisor polynomials.
// The remainder when data[0 : dataLen] is divided by divisor[0 : degree] is stored in result[0 : degree].
// All polynomials are in big endian, and the generator has an implicit leading 1 term.
static void reedSolomonComputeRemainder(const qr_u8 data[], int dataLen,
        const qr_u8 generator[], int degree, qr_u8 result[]) {
    assert(1 <= degree && degree <= qrcodegen_REED_SOLOMON_DEGREE_MAX);
    qr_memset(result, 0, degree);
    int i;
    for (i = 0; i < dataLen; i++) {  // Polynomial division
        qr_u8 factor = data[i] ^ result[0];
        qr_memmove(&result[0], &result[1], degree - 1);
        result[degree - 1] = 0;
        int j;
        for (j = 0; j < degree; j++)
            result[j] ^= reedSolomonMultiply(generator[j], factor);
    }
}

#undef qrcodegen_REED_SOLOMON_DEGREE_MAX


// Returns the product of the two given field elements modulo GF(2^8/0x11D).
static qr_u8 reedSolomonMultiply(qr_u8 x, qr_u8 y) {
    // Russian peasant multiplication
    qr_u8 z = 0;
    int i;
    for (i = 7; i >= 0; i--) {
        z = (qr_u8)((z << 1) ^ ((z >> 7) * 0x11D));
        z ^= ((y >> i) & 1) * x;
    }
    return z;
}



/*---- Drawing function modules ----*/

// Clears the given QR Code grid with light modules for the given
// version's size, then marks every function module as dark.
static void initializeFunctionModules(int version, qr_u8 qrcode[]) {
    // Initialize QR Code
    int qrsize = version * 4 + 17;
    qr_memset(qrcode, 0, (qrsize * qrsize + 7) / 8 + 1);
    qrcode[0] = (qr_u8)qrsize;

    // Fill horizontal and vertical timing patterns
    fillRectangle(6, 0, 1, qrsize, qrcode);
    fillRectangle(0, 6, qrsize, 1, qrcode);

    // Fill 3 finder patterns (all corners except bottom right) and format bits
    fillRectangle(0, 0, 9, 9, qrcode);
    fillRectangle(qrsize - 8, 0, 8, 9, qrcode);
    fillRectangle(0, qrsize - 8, 9, 8, qrcode);

    // Fill numerous alignment patterns
    qr_u8 alignPatPos[7];
    int numAlign = getAlignmentPatternPositions(version, alignPatPos);
    int i, j;
    for (i = 0; i < numAlign; i++) {
        for (j = 0; j < numAlign; j++) {
            // Don't draw on the three finder corners
            if (!((i == 0 && j == 0) || (i == 0 && j == numAlign - 1) || (i == numAlign - 1 && j == 0)))
                fillRectangle(alignPatPos[i] - 2, alignPatPos[j] - 2, 5, 5, qrcode);
        }
    }

    // Fill version blocks
    if (version >= 7) {
        fillRectangle(qrsize - 11, 0, 3, 6, qrcode);
        fillRectangle(0, qrsize - 11, 6, 3, qrcode);
    }
}


// Draws light function modules and possibly some dark modules onto the given QR Code, without changing
// non-function modules. This does not draw the format bits.
static void drawLightFunctionModules(qr_u8 qrcode[], int version) {
    // Draw horizontal and vertical timing patterns
    int qrsize = qrcodegen_getSize(qrcode);
    int i;
    for (i = 7; i < qrsize - 7; i += 2) {
        setModuleBounded(qrcode, 6, i, 0);
        setModuleBounded(qrcode, i, 6, 0);
    }

    // Draw 3 finder patterns (all corners except bottom right; overwrites some timing modules)
    int dy, dx;
    for (dy = -4; dy <= 4; dy++) {
        for (dx = -4; dx <= 4; dx++) {
            int dist = qr_abs(dx);
            if (qr_abs(dy) > dist)
                dist = qr_abs(dy);
            if (dist == 2 || dist == 4) {
                setModuleUnbounded(qrcode, 3 + dx, 3 + dy, 0);
                setModuleUnbounded(qrcode, qrsize - 4 + dx, 3 + dy, 0);
                setModuleUnbounded(qrcode, 3 + dx, qrsize - 4 + dy, 0);
            }
        }
    }

    // Draw numerous alignment patterns
    qr_u8 alignPatPos[7];
    int numAlign = getAlignmentPatternPositions(version, alignPatPos);
    int ai, aj;
    for (ai = 0; ai < numAlign; ai++) {
        for (aj = 0; aj < numAlign; aj++) {
            if ((ai == 0 && aj == 0) || (ai == 0 && aj == numAlign - 1) || (ai == numAlign - 1 && aj == 0))
                continue;  // Don't draw on the three finder corners
            for (dy = -1; dy <= 1; dy++) {
                for (dx = -1; dx <= 1; dx++)
                    setModuleBounded(qrcode, alignPatPos[ai] + dx, alignPatPos[aj] + dy, dx == 0 && dy == 0);
            }
        }
    }

    // Draw version blocks
    if (version >= 7) {
        // Calculate error correction code and pack bits
        int rem = version;  // version is uint6, in the range [7, 40]
        for (i = 0; i < 12; i++)
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
        long bits = (long)version << 12 | rem;  // uint18
        assert(bits >> 18 == 0);

        // Draw two copies
        for (i = 0; i < 6; i++) {
            int j;
            for (j = 0; j < 3; j++) {
                int k = qrsize - 11 + j;
                setModuleBounded(qrcode, k, i, (bits & 1) != 0);
                setModuleBounded(qrcode, i, k, (bits & 1) != 0);
                bits >>= 1;
            }
        }
    }
}


// Draws two copies of the format bits (with its own error correction code) based
// on the given mask and error correction level.
static void drawFormatBits(enum qrcodegen_Ecc ecl, enum qrcodegen_Mask mask, qr_u8 qrcode[]) {
    // Calculate error correction code and pack bits
    assert(0 <= (int)mask && (int)mask <= 7);
    static const int table[] = {1, 0, 3, 2};
    int data = table[(int)ecl] << 3 | (int)mask;  // errCorrLvl is uint2, mask is uint3
    int rem = data;
    int i;
    for (i = 0; i < 10; i++)
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    int bits = (data << 10 | rem) ^ 0x5412;  // uint15
    assert(bits >> 15 == 0);

    // Draw first copy
    for (i = 0; i <= 5; i++)
        setModuleBounded(qrcode, 8, i, getBit(bits, i));
    setModuleBounded(qrcode, 8, 7, getBit(bits, 6));
    setModuleBounded(qrcode, 8, 8, getBit(bits, 7));
    setModuleBounded(qrcode, 7, 8, getBit(bits, 8));
    for (i = 9; i < 15; i++)
        setModuleBounded(qrcode, 14 - i, 8, getBit(bits, i));

    // Draw second copy
    int qrsize = qrcodegen_getSize(qrcode);
    for (i = 0; i < 8; i++)
        setModuleBounded(qrcode, qrsize - 1 - i, 8, getBit(bits, i));
    for (i = 8; i < 15; i++)
        setModuleBounded(qrcode, 8, qrsize - 15 + i, getBit(bits, i));
    setModuleBounded(qrcode, 8, qrsize - 8, 1);  // Always dark
}


// Calculates and stores an ascending list of positions of alignment patterns
// for this version number, returning the length of the list (in the range [0,7]).
static int getAlignmentPatternPositions(int version, qr_u8 result[7]) {
    if (version == 1)
        return 0;
    int numAlign = version / 7 + 2;
    int step = (version * 8 + numAlign * 3 + 5) / (numAlign * 4 - 4) * 2;
    int i, pos;
    for (i = numAlign - 1, pos = version * 4 + 10; i >= 1; i--, pos -= step)
        result[i] = (qr_u8)pos;
    result[0] = 6;
    return numAlign;
}


// Sets every module in the range [left : left + width] * [top : top + height] to dark.
static void fillRectangle(int left, int top, int width, int height, qr_u8 qrcode[]) {
    int dy, dx;
    for (dy = 0; dy < height; dy++) {
        for (dx = 0; dx < width; dx++)
            setModuleBounded(qrcode, left + dx, top + dy, 1);
    }
}



/*---- Drawing data modules and masking ----*/

// Draws the raw codewords (including data and ECC) onto the given QR Code.
static void drawCodewords(const qr_u8 data[], int dataLen, qr_u8 qrcode[]) {
    int qrsize = qrcodegen_getSize(qrcode);
    int i = 0;  // Bit index into the data
    // Do the funny zigzag scan
    int right;
    for (right = qrsize - 1; right >= 1; right -= 2) {  // Index of right column in each column pair
        if (right == 6)
            right = 5;
        int vert;
        for (vert = 0; vert < qrsize; vert++) {  // Vertical counter
            int j;
            for (j = 0; j < 2; j++) {
                int x = right - j;  // Actual x coordinate
                int upward = ((right + 1) & 2) == 0;
                int y = upward ? qrsize - 1 - vert : vert;  // Actual y coordinate
                if (!getModuleBounded(qrcode, x, y) && i < dataLen * 8) {
                    int dark = getBit(data[i >> 3], 7 - (i & 7));
                    setModuleBounded(qrcode, x, y, dark);
                    i++;
                }
                // If this QR Code has any remainder bits (0 to 7), they were assigned as
                // 0/light by the constructor and are left unchanged by this method
            }
        }
    }
    assert(i == dataLen * 8);
}


// XORs the codeword modules in this QR Code with the given mask pattern
// and given pattern of function modules.
static void applyMask(const qr_u8 functionModules[], qr_u8 qrcode[], enum qrcodegen_Mask mask) {
    assert(0 <= (int)mask && (int)mask <= 7);  // Disallows qrcodegen_Mask_AUTO
    int qrsize = qrcodegen_getSize(qrcode);
    int y, x;
    for (y = 0; y < qrsize; y++) {
        for (x = 0; x < qrsize; x++) {
            if (getModuleBounded(functionModules, x, y))
                continue;
            int invert;
            switch ((int)mask) {
                case 0:  invert = (x + y) % 2 == 0;                    break;
                case 1:  invert = y % 2 == 0;                          break;
                case 2:  invert = x % 3 == 0;                          break;
                case 3:  invert = (x + y) % 3 == 0;                    break;
                case 4:  invert = (x / 3 + y / 2) % 2 == 0;            break;
                case 5:  invert = x * y % 2 + x * y % 3 == 0;          break;
                case 6:  invert = (x * y % 2 + x * y % 3) % 2 == 0;    break;
                case 7:  invert = ((x + y) % 2 + x * y % 3) % 2 == 0;  break;
                default:  assert(0);  return;
            }
            int val = getModuleBounded(qrcode, x, y);
            setModuleBounded(qrcode, x, y, val ^ invert);
        }
    }
}


// Calculates and returns the penalty score based on state of the given QR Code's current modules.
static long getPenaltyScore(const qr_u8 qrcode[]) {
    int qrsize = qrcodegen_getSize(qrcode);
    long result = 0;
    int y, x;

    // Adjacent modules in row having same color, and finder-like patterns
    for (y = 0; y < qrsize; y++) {
        int runColor = 0;
        int runX = 0;
        int runHistory[7] = {0};
        for (x = 0; x < qrsize; x++) {
            if (getModuleBounded(qrcode, x, y) == runColor) {
                runX++;
                if (runX == 5)
                    result += PENALTY_N1;
                else if (runX > 5)
                    result++;
            } else {
                finderPenaltyAddHistory(runX, runHistory, qrsize);
                if (!runColor)
                    result += finderPenaltyCountPatterns(runHistory, qrsize) * PENALTY_N3;
                runColor = getModuleBounded(qrcode, x, y);
                runX = 1;
            }
        }
        result += finderPenaltyTerminateAndCount(runColor, runX, runHistory, qrsize) * PENALTY_N3;
    }
    // Adjacent modules in column having same color, and finder-like patterns
    for (x = 0; x < qrsize; x++) {
        int runColor = 0;
        int runY = 0;
        int runHistory[7] = {0};
        for (y = 0; y < qrsize; y++) {
            if (getModuleBounded(qrcode, x, y) == runColor) {
                runY++;
                if (runY == 5)
                    result += PENALTY_N1;
                else if (runY > 5)
                    result++;
            } else {
                finderPenaltyAddHistory(runY, runHistory, qrsize);
                if (!runColor)
                    result += finderPenaltyCountPatterns(runHistory, qrsize) * PENALTY_N3;
                runColor = getModuleBounded(qrcode, x, y);
                runY = 1;
            }
        }
        result += finderPenaltyTerminateAndCount(runColor, runY, runHistory, qrsize) * PENALTY_N3;
    }

    // 2*2 blocks of modules having same color
    for (y = 0; y < qrsize - 1; y++) {
        for (x = 0; x < qrsize - 1; x++) {
            int color = getModuleBounded(qrcode, x, y);
            if (color == getModuleBounded(qrcode, x + 1, y) &&
                color == getModuleBounded(qrcode, x, y + 1) &&
                color == getModuleBounded(qrcode, x + 1, y + 1))
                result += PENALTY_N2;
        }
    }

    // Balance of dark and light modules
    int dark = 0;
    for (y = 0; y < qrsize; y++) {
        for (x = 0; x < qrsize; x++) {
            if (getModuleBounded(qrcode, x, y))
                dark++;
        }
    }
    int total = qrsize * qrsize;  // Note that size is odd, so dark/total != 1/2
    // Compute the smallest integer k >= 0 such that (45-5k)% <= dark/total <= (55+5k)%
    int k = (int)((qr_labs(dark * 20L - total * 10L) + total - 1) / total) - 1;
    assert(0 <= k && k <= 9);
    result += k * PENALTY_N4;
    assert(0 <= result && result <= 2568888L);
    return result;
}


// Can only be called immediately after a light run is added, and
// returns either 0, 1, or 2.
static int finderPenaltyCountPatterns(const int runHistory[7], int qrsize) {
    int n = runHistory[1];
    assert(n <= qrsize * 3);  (void)qrsize;
    int core = n > 0 && runHistory[2] == n && runHistory[3] == n * 3 && runHistory[4] == n && runHistory[5] == n;
    return (core && runHistory[0] >= n * 4 && runHistory[6] >= n ? 1 : 0)
         + (core && runHistory[6] >= n * 4 && runHistory[0] >= n ? 1 : 0);
}


// Must be called at the end of a line (row or column) of modules.
static int finderPenaltyTerminateAndCount(int currentRunColor, int currentRunLength, int runHistory[7], int qrsize) {
    if (currentRunColor) {  // Terminate dark run
        finderPenaltyAddHistory(currentRunLength, runHistory, qrsize);
        currentRunLength = 0;
    }
    currentRunLength += qrsize;  // Add light border to final run
    finderPenaltyAddHistory(currentRunLength, runHistory, qrsize);
    return finderPenaltyCountPatterns(runHistory, qrsize);
}


// Pushes the given value to the front and drops the last value.
static void finderPenaltyAddHistory(int currentRunLength, int runHistory[7], int qrsize) {
    if (runHistory[0] == 0)
        currentRunLength += qrsize;  // Add light border to initial run
    qr_memmove((qr_u8 *)&runHistory[1], (const qr_u8 *)&runHistory[0], 6 * (int)sizeof(runHistory[0]));
    runHistory[0] = currentRunLength;
}



/*---- Basic QR Code information ----*/

// Public function - see documentation comment in header file.
int qrcodegen_getSize(const qr_u8 qrcode[]) {
    assert(qrcode != 0);
    int result = qrcode[0];
    assert((qrcodegen_VERSION_MIN * 4 + 17) <= result
        && result <= (qrcodegen_VERSION_MAX * 4 + 17));
    return result;
}


// Public function - see documentation comment in header file.
int qrcodegen_getModule(const qr_u8 qrcode[], int x, int y) {
    assert(qrcode != 0);
    int qrsize = qrcode[0];
    return (0 <= x && x < qrsize && 0 <= y && y < qrsize) && getModuleBounded(qrcode, x, y);
}


// Returns the color of the module at the given coordinates, which must be in bounds.
static int getModuleBounded(const qr_u8 qrcode[], int x, int y) {
    int qrsize = qrcode[0];
    assert(21 <= qrsize && qrsize <= 177 && 0 <= x && x < qrsize && 0 <= y && y < qrsize);
    int index = y * qrsize + x;
    return getBit(qrcode[(index >> 3) + 1], index & 7);
}


// Sets the color of the module at the given coordinates, which must be in bounds.
static void setModuleBounded(qr_u8 qrcode[], int x, int y, int isDark) {
    int qrsize = qrcode[0];
    assert(21 <= qrsize && qrsize <= 177 && 0 <= x && x < qrsize && 0 <= y && y < qrsize);
    int index = y * qrsize + x;
    int bitIndex = index & 7;
    int byteIndex = (index >> 3) + 1;
    if (isDark)
        qrcode[byteIndex] |= 1 << bitIndex;
    else
        qrcode[byteIndex] &= (1 << bitIndex) ^ 0xFF;
}


// Sets the color of the module at the given coordinates, doing nothing if out of bounds.
static void setModuleUnbounded(qr_u8 qrcode[], int x, int y, int isDark) {
    int qrsize = qrcode[0];
    if (0 <= x && x < qrsize && 0 <= y && y < qrsize)
        setModuleBounded(qrcode, x, y, isDark);
}


// Returns true iff the i'th bit of x is set to 1. Requires x >= 0 and 0 <= i <= 14.
static int getBit(int x, int i) {
    return ((x >> i) & 1) != 0;
}



/*---- Segment handling (byte mode only) ----*/

// Returns the number of data bits needed to represent a segment
// containing the given number of characters using the given mode. Notes:
// - Returns LENGTH_OVERFLOW on failure, i.e. numChars > INT16_MAX-equivalent
//   or the number of needed bits exceeds it.
// - For byte mode, numChars measures the number of bytes.
static int calcSegmentBitLength(enum qrcodegen_Mode mode, int numChars) {
    (void)mode;  // Byte mode only in this port; see the file header comment.
    #define QR_INT16_MAX 32767
    if (numChars < 0 || numChars > QR_INT16_MAX)
        return LENGTH_OVERFLOW;
    long result = (long)numChars * 8;  // Byte mode: 8 bits per character
    assert(result >= 0);
    if (result > QR_INT16_MAX)
        return LENGTH_OVERFLOW;
    #undef QR_INT16_MAX
    return (int)result;
}


// Calculates the number of bits needed to encode the given segments at the given version.
static int getTotalBits(const struct qrcodegen_Segment segs[], int len, int version) {
    assert(segs != 0 || len == 0);
    long result = 0;
    int i;
    for (i = 0; i < len; i++) {
        int numChars  = segs[i].numChars;
        int bitLength = segs[i].bitLength;
        int ccbits = numCharCountBits(segs[i].mode, version);
        assert(0 <= ccbits && ccbits <= 16);
        if (numChars >= (1L << ccbits))
            return LENGTH_OVERFLOW;  // The segment's length doesn't fit the field's bit width
        result += 4L + ccbits + bitLength;
        if (result > 32767L)
            return LENGTH_OVERFLOW;  // The sum might overflow an int type
    }
    return (int)result;
}


// Returns the bit width of the character count field for a segment in the given mode
// in a QR Code at the given version number.
static int numCharCountBits(enum qrcodegen_Mode mode, int version) {
    assert(qrcodegen_VERSION_MIN <= version && version <= qrcodegen_VERSION_MAX);
    (void)mode;  // Byte mode only in this port; see the file header comment.
    int i = (version + 7) / 17;
    static const int temp[] = { 8, 16, 16};
    return temp[i];
}

#undef LENGTH_OVERFLOW
