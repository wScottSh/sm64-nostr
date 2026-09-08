#ifndef PIPELINE_QR_ADAPTER_H
#define PIPELINE_QR_ADAPTER_H

/*
 * The QR encode adapter (spec #24, sub-issue #27) -- the pipeline-internal
 * seam in front of the ported qrcodegen.c/h (Nayuki qrcodegen, C99, hidden
 * behind this header). Like pack_adapter.h/build_event.h, this file is
 * pure: no MarioState, no globals, no N64 headers. It is compiled a second
 * time, unmodified, into the host test tool (tools/pipeline_test).
 *
 * Scope discipline (spec #24, sub-issue #27): this exposes the QR encoder
 * as a standalone internal seam, exercised directly by the host test
 * tool's round-trip test. It is NOT yet wired into build_event()'s real
 * output -- doing so would pull in the real packed-payload contents from
 * #28 (serialize/id) and #29 (signing), which are out of scope here. The
 * encoder is called only from within src/pipeline/ (this file and, in a
 * later sub-issue, build_event.c); game glue never calls qrcodegen.c or
 * this adapter directly.
 *
 * Version/ECC choice: fixed version 6, error correction level MEDIUM.
 * getNumDataCodewords(6, MEDIUM) = getNumRawDataModules(6)/8 -
 * ECC_CODEWORDS_PER_BLOCK[MEDIUM][6] * NUM_ERROR_CORRECTION_BLOCKS[MEDIUM][6]
 * = 172 - 16*4 = 108 data CODEWORDS total (PIPELINE_QR_DATA_CODEWORDS) --
 * but that figure includes the mandatory 4-bit mode indicator + 8-bit
 * byte-mode character count header (versions 1-9 use an 8-bit byte-mode
 * count field), so the actual usable PAYLOAD capacity is smaller:
 * floor((108*8 - 12) / 8) = 106 bytes (PIPELINE_QR_MAX_PAYLOAD_BYTES,
 * confirmed empirically against this exact encoder: 106 B round-trips,
 * 107 B is cleanly rejected). That is still comfortably above the ~88 B
 * packed payload budget (spec #24), with 18 bytes / ~20% headroom to
 * spare without needing to move to a larger (version 7+) code, and MEDIUM
 * (not LOW) error correction for realistic camera-scan robustness once
 * the renderer glue (#32, out of scope here) lands.
 */

#include "build_event.h"
#include "qrcodegen.h"

#define PIPELINE_QR_VERSION 6
#define PIPELINE_QR_ECC qrcodegen_Ecc_MEDIUM

/* Module grid side length: version*4+17 = 41 for version 6. */
#define PIPELINE_QR_MODULE_SIZE (PIPELINE_QR_VERSION * 4 + 17)

/* Size of the qrcodegen-format bitmap buffer (byte 0 = grid size, remaining
 * bytes = packed 1-bpp module bits): qrcodegen_BUFFER_LEN_FOR_VERSION(6). */
#define PIPELINE_QR_BUFFER_LEN qrcodegen_BUFFER_LEN_FOR_VERSION(PIPELINE_QR_VERSION)

/* Total data-codeword capacity of a version 6, ECC MEDIUM QR Code (header +
 * payload + terminator/padding): 108 bytes. See the file header comment. */
#define PIPELINE_QR_DATA_CODEWORDS 108

/* Usable BYTE-mode payload capacity after the mandatory 4-bit mode
 * indicator + 8-bit character count header: 106 bytes. See the derivation
 * in the file header comment above. This is the real over-budget boundary
 * payloads are rejected against, comfortably above the ~88 B packed
 * payload budget. */
#define PIPELINE_QR_MAX_PAYLOAD_BYTES 106

/*
 * pipeline_qr_encode: encodes payload[0 : payloadLen] as a fixed-version-6/
 * ECC-MEDIUM, BYTE-mode QR Code into out (a qrcodegen-format bitmap; read
 * it back via pipeline_qr_get_size/pipeline_qr_get_module).
 *
 * Returns nonzero (true) on success. Returns 0 (false) -- writing nothing
 * usable to out -- if payloadLen exceeds PIPELINE_QR_MAX_PAYLOAD_BYTES.
 * This is the clean, non-truncating rejection path for over-budget input:
 * callers must check the return value.
 */
int pipeline_qr_encode(const pipeline_u8 *payload, pipeline_u32 payloadLen,
                        pipeline_u8 out[PIPELINE_QR_BUFFER_LEN]);

/* Thin pass-throughs to qrcodegen_getSize/qrcodegen_getModule, so callers
 * outside src/pipeline never need to name those functions directly -- note
 * that qrcodegen.h's own public symbols (the enums, qrcodegen_encodeBinary
 * itself) are still visible transitively via the #include above, since
 * this header's job is hiding qrcodegen.c's file-static internals, not its
 * declared public surface; nothing outside this file calls them, but the
 * compiler wouldn't stop anyone in src/pipeline from doing so. */
int pipeline_qr_get_size(const pipeline_u8 qrcode[PIPELINE_QR_BUFFER_LEN]);
int pipeline_qr_get_module(const pipeline_u8 qrcode[PIPELINE_QR_BUFFER_LEN], int x, int y);

#endif /* PIPELINE_QR_ADAPTER_H */
