#ifndef PIPELINE_BASE32_H
#define PIPELINE_BASE32_H

/*
 * The base32 codec (ADR-0006's airgap transport, spec #115 sub-issue #116):
 * a pipeline-internal seam encoding/decoding RFC 4648 section 6 base32
 * (uppercase A-Z2-7, no padding), sitting behind build_event() exactly like
 * sha256.h/secp256k1.h/qrcodegen.h -- each an internal port with its own
 * known-answer test, never called by game glue directly. Like those, this
 * file is pure C89: no MarioState, no globals, no N64 headers. It is
 * compiled a second time, unmodified, into the host test tool
 * (tools/pipeline_test).
 *
 * This is a reversible ENVELOPE around the existing v3 packed payload, not
 * a new payload format: base32-encoding the bytes pipeline_pack() already
 * produced, then reversing that exact transform on decode, changes nothing
 * about what crosses the airgap, only how it rides a QR alphanumeric
 * segment and a plaintext URL (docs/adr/0006). The alphabet itself lives in
 * transport_contract.h, the single shared source of truth this file and
 * fragment.h/.c/url.h/.c all derive from -- never a second, hand-duplicated
 * copy of the 32-character string.
 *
 * No padding on the wire: the reassembler is length-driven via the
 * fragment header's total-frame-count field (fragment.h), not '='
 * padding -- so this codec never emits or expects '='.
 */

#include "build_event.h"
#include "transport_contract.h"

/*
 * PIPELINE_BASE32_ENCODED_LEN: the exact number of base32 characters
 * pipeline_base32_encode() writes for inLen input bytes -- ceil(inLen*8/5),
 * i.e. ceil(bitLen/5) with no padding. A compile-time constant expression
 * (usable anywhere an array bound needs it, e.g. build_event.h's
 * PIPELINE_BUILT_BASE32_LEN, which duplicates this exact formula rather
 * than #including this header -- see that macro's own comment for why).
 */
#define PIPELINE_BASE32_ENCODED_LEN(inLen) ((((pipeline_u32)(inLen)) * 8u + 4u) / 5u)

/*
 * pipeline_base32_encode: encodes in[0 : inLen] as RFC 4648 section 6
 * base32 (uppercase A-Z2-7, no padding) into out. out must be at least
 * PIPELINE_BASE32_ENCODED_LEN(inLen) bytes (outCap is that bound, checked
 * defensively). Writes exactly PIPELINE_BASE32_ENCODED_LEN(inLen) bytes,
 * never NUL-terminated, and returns that count. Returns 0 -- writing
 * nothing -- if outCap is too small.
 */
pipeline_u32 pipeline_base32_encode(const pipeline_u8 *in, pipeline_u32 inLen,
                                     pipeline_u8 *out, pipeline_u32 outCap);

/*
 * pipeline_base32_decode: the inverse of pipeline_base32_encode. Decodes
 * in[0 : inLen] (uppercase A-Z2-7 only -- any other byte, including a
 * literal '=', is rejected) into out, writing floor(inLen*5/8) bytes and
 * setting *outLen to that count. out must be at least that many bytes
 * (outCap is that bound, checked defensively). Returns nonzero (true) on
 * success. Returns 0 (false) -- writing nothing usable to out -- if any
 * input byte is outside the base32 alphabet or outCap is too small.
 */
int pipeline_base32_decode(const pipeline_u8 *in, pipeline_u32 inLen,
                            pipeline_u8 *out, pipeline_u32 outCap, pipeline_u32 *outLen);

#endif /* PIPELINE_BASE32_H */
