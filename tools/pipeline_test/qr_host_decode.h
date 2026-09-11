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
 * decoder: it knows the fixed version (7, spec #52 sub-issue #53) and ECC
 * level (MEDIUM) ahead of time (matching qr_adapter.h's documented
 * choice), so it can skip finder-pattern detection/perspective correction
 * entirely and go straight to walking the same zigzag codeword-placement
 * order and function-module footprint that qrcodegen.c's
 * drawCodewords()/initializeFunctionModules() use -- including, at version
 * 7+, the two 3x6/6x3 version-info blocks initializeFunctionModules()'s own
 * drawVersion() reserves (absent below version 7, which is why this map
 * previously had no such blocks) -- then apply the mask recovered from the
 * format-info bits (qr_adapter.h now pins one fixed mask at encode time,
 * but this decoder still recovers whichever mask was actually used from
 * the format-info bits, exactly as a real reader must, rather than
 * assuming the encoder's constant), de-interleave the error correction
 * blocks (four, for version 7 / ECC MEDIUM), and parse the resulting
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

/*
 * qr_host_decode_alphanumeric: the ALPHANUMERIC-mode counterpart of
 * qr_host_decode() above (spec #115, sub-issue #116), for QR bitmaps
 * produced by pipeline_qr_encode_alphanumeric() (qr_adapter.h) -- ADR-0006's
 * URL-wrapped fragment frames. Decodes qrcode[] into outText[0 : *outTextLen]
 * (the recovered alphanumeric-charset text, e.g. a full "HTTPS://..." URL),
 * NOT NUL-terminated. outCap is outText's capacity; if the decoded text
 * would not fit, returns 0 without writing to outText fully. Returns
 * nonzero (true) and sets *outTextLen on success.
 */
int qr_host_decode_alphanumeric(const unsigned char *qrcode, unsigned char *outText, int outCap, int *outTextLen);

/*
 * qr_host_decode_mixed: the TWO-SEGMENT counterpart of
 * qr_host_decode_alphanumeric() above (spec #122, sub-issue #123), for QR
 * bitmaps produced by pipeline_qr_encode_two_segment() (qr_adapter.h) --
 * #101's ratified `<BASE>#<SEQ>/<TOTAL>/<PAYLOAD>` frames, where the
 * verbatim `<BASE>#` prefix rides a BYTE segment and the fragment tail
 * rides ALPHANUMERIC. Decodes both segments in order and concatenates them
 * into outText[0 : *outTextLen] -- i.e. the exact full URL text
 * pipeline_url_wrap() produced -- NOT NUL-terminated. outCap is outText's
 * capacity; if the decoded text would not fit, returns 0 without writing
 * to outText fully. Returns nonzero (true) and sets *outTextLen on
 * success.
 */
int qr_host_decode_mixed(const unsigned char *qrcode, unsigned char *outText, int outCap, int *outTextLen);

#endif /* QR_HOST_DECODE_H */
