#ifndef QR_HOST_DECODE_H
#define QR_HOST_DECODE_H

/*
 * HOST-ONLY QR bitmap decoder (spec #24, sub-issue #27). Lives under
 * tools/pipeline_test, never under src/pipeline/, so it can never end up
 * in the ROM's object graph -- see the Makefile comment.
 *
 * This decoder reads a finished qrcodegen-format bitmap (exactly what
 * pipeline_qr_encode()/qr_adapter.h produce, fixed at PIPELINE_QR_VERSION/
 * PIPELINE_QR_ECC) back to the original payload bytes, WITHOUT reaching
 * into qrcodegen.c's internals: its only input is the module grid, read
 * through pipeline_qr_get_size()/pipeline_qr_get_module() -- the same
 * public accessors any real reader (camera scan, companion app) would use.
 *
 * It is "structural" rather than a general-purpose camera-image QR
 * decoder: it knows the fixed version (6) and ECC level (MEDIUM) ahead of
 * time (matching qr_adapter.h's documented choice), so it can skip
 * finder-pattern detection/perspective correction entirely and go straight
 * to walking the same zigzag codeword-placement order and function-module
 * footprint that qrcodegen.c's drawCodewords()/initializeFunctionModules()
 * use, then apply the mask recovered from the format-info bits (the mask
 * is chosen dynamically by qrcodegen_Mask_AUTO at encode time, so this is
 * a real decode, not an assumption), de-interleave the error correction
 * blocks (four, for version 6 / ECC MEDIUM), and parse the resulting
 * bitstream's mode indicator +
 * character count + byte-mode data directly (no Reed-Solomon error
 * correction is performed: this decodes a bitmap this same test built in
 * memory, never a noisy scan, so nothing has actually corrupted the
 * codewords).
 */

/*
 * qr_host_decode: decodes qrcode[] (a pipeline_qr_encode()-produced
 * bitmap) into out[0 : *outLen]. outCap is out's capacity; if the decoded
 * payload would not fit, returns 0 without writing to out fully. Returns
 * nonzero (true) and sets *outLen on success.
 */
int qr_host_decode(const unsigned char *qrcode, unsigned char *out, int outCap, int *outLen);

#endif /* QR_HOST_DECODE_H */
