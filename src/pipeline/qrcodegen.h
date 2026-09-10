#ifndef PIPELINE_QRCODEGEN_H
#define PIPELINE_QRCODEGEN_H

/*
 * Internal C99 port (spec #24, sub-issue #27) of a byte-mode-only subset of
 * Project Nayuki's QR Code generator library (C):
 *   https://github.com/nayuki/QR-Code-generator (c/qrcodegen.h, c/qrcodegen.c)
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
 * This is a genuine C99 port, not a verbatim vendor drop: the ROM build
 * compiles under -nostdinc/-ffreestanding (see build_event.h's own note on
 * why it can't use <stdint.h>), so this header/its .c never include
 * <assert.h>/<stdbool.h>/<stddef.h>/<stdint.h>/<stdlib.h>/<string.h> --
 * qrcodegen.c supplies drop-in local equivalents instead. The public
 * surface is also trimmed to exactly what the pipeline needs: encoding an
 * arbitrary byte buffer as a single BYTE-mode segment, or a validated
 * alphanumeric-charset text buffer as a single ALPHANUMERIC-mode segment
 * (never numeric, kanji, or ECI, and never upstream's general free-form
 * multi-segment text API), matching this repo's "hide the ported library
 * behind the pipeline interface" rule (spec #24 story 21) -- upstream's
 * text/segment-array API surface is dropped entirely rather than exposed
 * unused. The alphanumeric path (spec #115, sub-issue #116) is a second,
 * equally narrow single-segment/single-mode entry point alongside the
 * original BYTE-mode one, added for ADR-0006's airgap transport (URL-
 * wrapped fragment text rides the denser alphanumeric charset).
 *
 * Like port_stub_c99.c, this file is C99 (block-scope `for` loop
 * declarations throughout) and goes through the root Makefile's per-object
 * C99 carve-out (PIPELINE_C99_PORT_O), never the whole-build COMPILER
 * knob. It is compiled unmodified into both the ROM build and the host
 * test tool (tools/pipeline_test).
 */

typedef unsigned char qr_u8;

/* Mirrors upstream enum qrcodegen_Ecc exactly (ordinal order is load-bearing:
 * internal tables are indexed by it, and boosting only ever walks upward). */
enum qrcodegen_Ecc {
    qrcodegen_Ecc_LOW = 0,
    qrcodegen_Ecc_MEDIUM,
    qrcodegen_Ecc_QUARTILE,
    qrcodegen_Ecc_HIGH
};

/* Mirrors upstream enum qrcodegen_Mask exactly. */
enum qrcodegen_Mask {
    qrcodegen_Mask_AUTO = -1,
    qrcodegen_Mask_0 = 0,
    qrcodegen_Mask_1,
    qrcodegen_Mask_2,
    qrcodegen_Mask_3,
    qrcodegen_Mask_4,
    qrcodegen_Mask_5,
    qrcodegen_Mask_6,
    qrcodegen_Mask_7
};

#define qrcodegen_VERSION_MIN 1
#define qrcodegen_VERSION_MAX 40

/* Same formula as upstream qrcodegen_BUFFER_LEN_FOR_VERSION. */
#define qrcodegen_BUFFER_LEN_FOR_VERSION(n) ((((n) * 4 + 17) * ((n) * 4 + 17) + 7) / 8 + 1)

/*
 * qrcodegen_encodeBinary: byte-mode-only counterpart of upstream's function
 * of the same name (same semantics, `int` in place of `bool`/`size_t`).
 * Encodes dataAndTemp[0 : dataLen] as a single BYTE-mode segment, searching
 * versions [minVersion, maxVersion] for the smallest that fits at ecl
 * (silently raised to a higher ECC level, never lower, if boostEcl is
 * nonzero and it still fits), and writes the finished, masked QR Code into
 * qrcode[].
 *
 * Returns nonzero (true) on success. Returns 0 (false) -- writing nothing
 * usable to qrcode (qrcode[0] is set to 0, an invalid size) -- if the data
 * does not fit any version in range at the given ecl. This is the clean
 * rejection path for over-budget input: callers must check the return
 * value, and no truncated/partial QR Code is ever produced.
 *
 * dataAndTemp[0 : len] and qrcode[0 : len], where
 * len = qrcodegen_BUFFER_LEN_FOR_VERSION(maxVersion), must not overlap.
 * dataAndTemp is clobbered as scratch space; only qrcode holds the result.
 */
int qrcodegen_encodeBinary(qr_u8 dataAndTemp[], int dataLen, qr_u8 qrcode[],
                            enum qrcodegen_Ecc ecl, int minVersion, int maxVersion,
                            enum qrcodegen_Mask mask, int boostEcl);

/*
 * qrcodegen_encodeAlphanumeric: ALPHANUMERIC-mode counterpart of
 * qrcodegen_encodeBinary() above (spec #115, sub-issue #116). Encodes
 * text[0 : textLen] as a single ALPHANUMERIC-mode segment -- text must
 * contain only the QR alphanumeric charset (0-9, A-Z, space,
 * $ % * + - . / :); any other byte is rejected -- searching versions
 * [minVersion, maxVersion] for the smallest that fits at ecl (silently
 * raised to a higher ECC level, never lower, if boostEcl is nonzero and it
 * still fits), and writes the finished, masked QR Code into qrcode[].
 *
 * Returns nonzero (true) on success. Returns 0 (false) -- writing nothing
 * usable to qrcode (qrcode[0] is set to 0, an invalid size) -- if text
 * contains a non-alphanumeric-charset byte or the data does not fit any
 * version in range at the given ecl. This is the clean rejection path for
 * invalid/over-budget input: callers must check the return value, and no
 * truncated/partial QR Code is ever produced.
 *
 * Unlike qrcodegen_encodeBinary(), text[] is read-only input, not scratch:
 * tempBuffer[] (length qrcodegen_BUFFER_LEN_FOR_VERSION(maxVersion)) is the
 * separate scratch buffer this function needs for error-correction
 * interleaving and the function-module map, mirroring the tempBuffer
 * qrcodegen_encodeBinary() borrows from its caller's dataAndTemp argument.
 * text[]/tempBuffer[]/qrcode[] must not overlap.
 */
int qrcodegen_encodeAlphanumeric(const qr_u8 text[], int textLen, qr_u8 qrcode[], qr_u8 tempBuffer[],
                                  enum qrcodegen_Ecc ecl, int minVersion, int maxVersion,
                                  enum qrcodegen_Mask mask, int boostEcl);

/* Same semantics as upstream qrcodegen_getSize/qrcodegen_getModule
 * (nonzero/zero in place of bool). */
int qrcodegen_getSize(const qr_u8 qrcode[]);
int qrcodegen_getModule(const qr_u8 qrcode[], int x, int y);

#endif /* PIPELINE_QRCODEGEN_H */
