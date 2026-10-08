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
 * Version/ECC choice: fixed version 4 (33x33), error correction level
 * MEDIUM, with a SINGLE FIXED MASK (not qrcodegen_Mask_AUTO). Spec #52 /
 * sub-issue #53 pinned version 7 so format v2's whole payload fit one
 * symbol; ADR-0006's multi-frame transport retired that need, and issue
 * #152 then dropped to version 4 so each module is larger on screen (a
 * lower-density symbol is easier to scan off a CRT) at the cost of more
 * frames (docs/research/qr-density-tradeoffs.md section 9, ADR-0006's
 * #152 amendment). Version 3 is not viable while PIPELINE_URL_BASE stays
 * 27 bytes: the fixed BYTE segment leaves too little room per frame
 * (18 frames for the default build).
 *
 * getNumDataCodewords(4, MEDIUM) = getNumRawDataModules(4)/8 -
 * ECC_CODEWORDS_PER_BLOCK[MEDIUM][4] * NUM_ERROR_CORRECTION_BLOCKS[MEDIUM][4]
 * = 100 - 18*2 = 64 data CODEWORDS total (PIPELINE_QR_DATA_CODEWORDS).
 * That figure includes the mandatory 4-bit mode indicator + 8-bit
 * byte-mode character count header (versions 1-9 use an 8-bit byte-mode
 * count field), so the usable BYTE-mode PAYLOAD capacity is
 * floor((64*8 - 12) / 8) = 62 bytes (PIPELINE_QR_MAX_PAYLOAD_BYTES,
 * confirmed against this exact encoder by the host round-trip test: 62 B
 * round-trips, 63 B is cleanly rejected). MEDIUM (not LOW) error
 * correction is kept for realistic camera-scan robustness (glare/moire/CRT
 * artifacts, see the research doc's section 3).
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

#define PIPELINE_QR_VERSION 4
#define PIPELINE_QR_ECC qrcodegen_Ecc_MEDIUM

/* Fixed mask pattern (0-7) passed to qrcodegen_encodeBinary() instead of
 * qrcodegen_Mask_AUTO -- see the file header comment above. */
#define PIPELINE_QR_MASK qrcodegen_Mask_0

/* Module grid side length: version*4+17 = 33 for version 4. */
#define PIPELINE_QR_MODULE_SIZE (PIPELINE_QR_VERSION * 4 + 17)

/* Size of the qrcodegen-format bitmap buffer (byte 0 = grid size, remaining
 * bytes = packed 1-bpp module bits). */
#define PIPELINE_QR_BUFFER_LEN qrcodegen_BUFFER_LEN_FOR_VERSION(PIPELINE_QR_VERSION)

/* Total data-codeword capacity of a version 4, ECC MEDIUM QR Code (header +
 * payload + terminator/padding): 64 bytes. See the file header comment. */
#define PIPELINE_QR_DATA_CODEWORDS 64

/* Usable BYTE-mode payload capacity of a single version 4, ECC MEDIUM QR
 * symbol, after the mandatory 4-bit mode indicator + 8-bit character count
 * header: 62 bytes. See the derivation in the file header comment above.
 * This is the real over-budget boundary a single pipeline_qr_encode() call
 * rejects against (qr_adapter.c) -- PER CALL, PER SYMBOL geometry, not a
 * build-wide total-payload cap: format v3's packed payload
 * (PIPELINE_BUILT_PAYLOAD_SIZE, 113-140 B depending on this build's own
 * tag/name lengths) is no longer QR-encoded directly via this BYTE-mode
 * path or bounded by this constant at all (ADR-0006's multi-frame
 * transport, spec #115, sub-issue #117, retired that ceiling -- the packed
 * payload is base32-encoded, fragmented, and URL-wrapped into N two-segment
 * frames instead (spec #122, sub-issue #123: a BYTE segment for the
 * verbatim base URL + '#', an ALPHANUMERIC segment for the fragment tail);
 * see PIPELINE_QR_ALNUM_MAX_CHARS below and build_event.h's own bit-budget
 * derivation). pipeline_qr_encode() itself (BYTE mode) remains a
 * real, independently useful seam -- exercised directly by the host test
 * tool's own round-trip tests -- so this constant and its rejection
 * boundary stay exactly as they always were for that one call. */
#define PIPELINE_QR_MAX_PAYLOAD_BYTES 62

/*
 * Usable ALPHANUMERIC-mode character capacity of a version 4, ECC MEDIUM QR
 * Code (spec #115, sub-issue #116 -- ADR-0006's airgap transport wraps
 * every fragment as a plaintext URL, which rides this denser mode rather
 * than BYTE): after the mandatory 4-bit mode indicator + 9-bit alphanumeric
 * character-count header (versions 1-9), 512 - 13 = 499 data bits remain.
 * Alphanumeric mode packs 2 characters per 11 bits (a lone trailing
 * character costs 6 bits): floor(499 / 11) = 45 pairs uses 495 bits,
 * leaving 4 bits, too few for a trailing single character (which needs
 * 6), so the maximum is exactly 45*2 = 90 characters -- confirmed against
 * this exact encoder by the host round-trip test: 90 chars round-trips,
 * 91 is cleanly rejected. This is the ceiling for a
 * SINGLE, standalone ALPHANUMERIC segment (pipeline_qr_encode_alphanumeric()'s
 * own budget); build_event.c's per-frame fragment tail no longer uses this
 * constant directly (spec #122, sub-issue #123: every frame is now a
 * two-segment QR -- see build_event.h's own PIPELINE_BUILT_ALNUM_SEG_HEADER_BITS/
 * PIPELINE_BUILT_ALNUM_BUDGET_BITS derivation, which build_event.c
 * cross-checks against this exact constant so the two can never silently
 * drift apart), not the packed-payload byte budget above (a different mode,
 * a different ceiling, and per ADR-0006 no longer a total-payload ceiling
 * at all -- see this header's own comment on PIPELINE_QR_MAX_PAYLOAD_BYTES
 * for why that one stays BYTE-mode-only and per-call, not a build-wide
 * total).
 */
#define PIPELINE_QR_ALNUM_MAX_CHARS 90

/*
 * pipeline_qr_encode: encodes payload[0 : payloadLen] as a fixed-version-4/
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

/*
 * pipeline_qr_encode_alphanumeric: encodes text[0 : textLen] as a fixed-
 * version-4/ECC-MEDIUM, ALPHANUMERIC-mode QR Code, with the same single
 * fixed mask (PIPELINE_QR_MASK) as pipeline_qr_encode() above, into out.
 * text must contain only the QR alphanumeric charset (0-9, A-Z, space,
 * $ % * + - . / :) -- ADR-0006's URL-wrapped fragment text (url.h) always
 * does, by construction.
 *
 * Returns nonzero (true) on success. Returns 0 (false) -- writing nothing
 * usable to out -- if textLen exceeds PIPELINE_QR_ALNUM_MAX_CHARS or text
 * contains a non-alphanumeric-charset byte. Callers must check the return
 * value.
 */
int pipeline_qr_encode_alphanumeric(const pipeline_u8 *text, pipeline_u32 textLen,
                                     pipeline_u8 out[PIPELINE_QR_BUFFER_LEN]);

/*
 * pipeline_qr_encode_two_segment: encodes byteData[0 : byteLen] as a BYTE
 * segment immediately followed by alnumText[0 : alnumLen] as an
 * ALPHANUMERIC segment, both in the same fixed-version-4/ECC-MEDIUM QR
 * Code with the same single fixed mask (PIPELINE_QR_MASK) as the two
 * functions above (spec #122, sub-issue #123 -- #101's ratified
 * `<BASE>#<SEQ>/<TOTAL>/<PAYLOAD>` template: the verbatim, possibly-mixed-
 * case `<BASE>#` prefix falls outside the QR alphanumeric charset, so it
 * rides BYTE while the `/`-delimited SEQ/TOTAL/PAYLOAD tail rides
 * ALPHANUMERIC). alnumText must contain only the QR alphanumeric charset
 * (0-9, A-Z, space, $ % * + - . / :) -- fragment.h's own fragment text
 * always does, by construction; byteData is unconstrained (any byte value
 * is legal in BYTE mode).
 *
 * Returns nonzero (true) on success. Returns 0 (false) -- writing nothing
 * usable to out -- if alnumText contains a non-alphanumeric-charset byte or
 * the combined segments exceed this fixed version/ECC's data capacity.
 * Callers must check the return value.
 */
int pipeline_qr_encode_two_segment(const pipeline_u8 *byteData, pipeline_u32 byteLen,
                                    const pipeline_u8 *alnumText, pipeline_u32 alnumLen,
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
