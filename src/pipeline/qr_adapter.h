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
 * Version/ECC choice (spec #52, sub-issue #53): fixed version 7 (45x45),
 * error correction level MEDIUM, with a SINGLE FIXED MASK (not
 * qrcodegen_Mask_AUTO). Bumped up from version 6 to make room for format
 * v2's self-contained payload (pubkey + created_at + tag, ~112-122 B,
 * docs/adr/0002) -- this sub-issue moves the OLD, unchanged v1 payload
 * (still 75 B) into the larger v7 symbol first, isolating the mechanical
 * geometry/mask change from the wire-format change (docs/qr-handoff-spec.md,
 * docs/research/qr-density-tradeoffs.md).
 *
 * getNumDataCodewords(7, MEDIUM) = getNumRawDataModules(7)/8 -
 * ECC_CODEWORDS_PER_BLOCK[MEDIUM][7] * NUM_ERROR_CORRECTION_BLOCKS[MEDIUM][7]
 * = 196 - 18*4 = 124 data CODEWORDS total (PIPELINE_QR_DATA_CODEWORDS) --
 * but that figure includes the mandatory 4-bit mode indicator + 8-bit
 * byte-mode character count header (versions 1-9 use an 8-bit byte-mode
 * count field), so the actual usable PAYLOAD capacity is smaller:
 * floor((124*8 - 12) / 8) = 122 bytes (PIPELINE_QR_MAX_PAYLOAD_BYTES,
 * matching docs/research/qr-density-tradeoffs.md's v7/MEDIUM capacity
 * table and confirmed empirically against this exact encoder: 122 B
 * round-trips, 123 B is cleanly rejected). MEDIUM (not LOW) error
 * correction is kept for realistic camera-scan robustness (glare/moiré/CRT
 * artifacts, see the research doc's §3) now that the renderer glue (#32)
 * has landed.
 *
 * The mask is pinned to a single fixed value (PIPELINE_QR_MASK) rather
 * than qrcodegen_Mask_AUTO: AUTO runs all 8 mask patterns and scores each
 * with a full-grid penalty pass to pick the best one, which is the
 * dominant compute cost of encoding (research doc §4) -- fixing one mask
 * eliminates that ~8x overhead on constrained hardware. Any of the 8 mask
 * values is a structurally valid QR Code (a fixed mask trades away the
 * penalty-score optimization, not correctness); mask 0 is chosen here with
 * no further significance. The host decoder (qr_host_decode.c) does not
 * need to know this constant -- it recovers whichever mask was actually
 * used from the format-info bits, exactly as a real reader would.
 */

#include "build_event.h"
#include "qrcodegen.h"

#define PIPELINE_QR_VERSION 7
#define PIPELINE_QR_ECC qrcodegen_Ecc_MEDIUM

/* Fixed mask pattern (0-7) passed to qrcodegen_encodeBinary() instead of
 * qrcodegen_Mask_AUTO -- see the file header comment above. */
#define PIPELINE_QR_MASK qrcodegen_Mask_0

/* Module grid side length: version*4+17 = 45 for version 7. */
#define PIPELINE_QR_MODULE_SIZE (PIPELINE_QR_VERSION * 4 + 17)

/* Size of the qrcodegen-format bitmap buffer (byte 0 = grid size, remaining
 * bytes = packed 1-bpp module bits): qrcodegen_BUFFER_LEN_FOR_VERSION(7). */
#define PIPELINE_QR_BUFFER_LEN qrcodegen_BUFFER_LEN_FOR_VERSION(PIPELINE_QR_VERSION)

/* Total data-codeword capacity of a version 7, ECC MEDIUM QR Code (header +
 * payload + terminator/padding): 124 bytes. See the file header comment. */
#define PIPELINE_QR_DATA_CODEWORDS 124

/* Usable BYTE-mode payload capacity after the mandatory 4-bit mode
 * indicator + 8-bit character count header: 122 bytes. See the derivation
 * in the file header comment above. This is the real over-budget boundary
 * payloads are rejected against, comfortably above the ~112-122 B
 * self-contained format v2 payload budget (docs/adr/0002) and the current
 * 75 B format v1 payload this sub-issue still ships. */
#define PIPELINE_QR_MAX_PAYLOAD_BYTES 122

/*
 * pipeline_qr_encode: encodes payload[0 : payloadLen] as a fixed-version-7/
 * ECC-MEDIUM, BYTE-mode QR Code, with a single fixed mask (PIPELINE_QR_MASK,
 * not qrcodegen_Mask_AUTO), into out (a qrcodegen-format bitmap; read it
 * back via pipeline_qr_get_size/pipeline_qr_get_module).
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
