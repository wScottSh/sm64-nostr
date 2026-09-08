#ifndef PIPELINE_PACK_ADAPTER_H
#define PIPELINE_PACK_ADAPTER_H

/*
 * The pack/unpack adapters for the packed QR payload (spec #24, sub-issue
 * #26; format v2 self-contained payload, spec #52 sub-issue #54). Both the
 * ROM pack side and the host unpack side derive their field layout from the
 * SAME generated format_descriptor.h (itself rendered from the single JSON
 * source src/pipeline/format_descriptor.json) -- never a hand-duplicated
 * literal.
 *
 * Like build_event.c/port_stub_c99.c, this file is pure: no MarioState, no
 * globals, no N64 headers. It is compiled a second time, unmodified, into
 * the host test tool (tools/pipeline_test).
 *
 * Format v2 packs the whole self-contained event onto the wire: capture's
 * run fields, CREATED_AT (u32 BE unix seconds), PUBKEY (32 B x-only),
 * TAG_LEN + TAG (0..10 ASCII bytes, the per-game `t` tag), and the 64-byte
 * Schnorr signature. `id` is never packed -- the companion recomputes it.
 * The tag is the one variable-length field, so:
 *   - pipeline_pack()'s output length varies with tagLen (the caller's own
 *     build-time tag length); out must be at least
 *     PIPELINE_FMT_TOTAL_SIZE(tagLen) bytes, and pipeline_pack() writes
 *     exactly that many.
 *   - pipeline_unpack() must be told the ACTUAL decoded byte length (inLen,
 *     e.g. from the QR decoder), since there is no fixed total size to
 *     assume -- it reads TAG_LEN off the wire, validates it (<=10) and
 *     validates inLen against PIPELINE_FMT_TOTAL_SIZE(that TAG_LEN) before
 *     trusting anything past that point. in/tagOut buffers must be sized to
 *     PIPELINE_PACK_MAX_SIZE / PIPELINE_PACK_MAX_TAG_LEN respectively, since
 *     an arbitrary (but format-v2-legal) incoming payload's tag can be up to
 *     the max.
 */

#include "build_event.h"
#include "format_descriptor.h"

/* Worst-case total payload size (tagLen at its max, 10 B) -- the right
 * buffer bound for host-side decode/scratch buffers that must hold any
 * legal incoming v2 payload, since an unpack caller doesn't know the
 * incoming tag length until it has already read TAG_LEN off the wire. */
#define PIPELINE_PACK_MAX_SIZE    PIPELINE_FMT_MAX_TOTAL_SIZE
#define PIPELINE_PACK_MAX_TAG_LEN PIPELINE_FMT_MAX_SIZE_TAG

/*
 * pipeline_unpack()'s return codes: 0 on success, or one of the three
 * distinct rejection reasons format v2 requires a conforming decoder to
 * distinguish (docs/qr-handoff-spec.md section 6) -- FORMAT_TAG mismatch,
 * an over-budget TAG_LEN, or a total length that doesn't match TAG_LEN.
 * Callers should treat ANY nonzero return as "reject, don't guess"; the
 * specific values exist so tests can assert the RIGHT rejection fired.
 */
#define PIPELINE_UNPACK_OK                  0
#define PIPELINE_UNPACK_ERR_BAD_FORMAT_TAG  1
#define PIPELINE_UNPACK_ERR_TAG_TOO_LONG    2
#define PIPELINE_UNPACK_ERR_WRONG_LENGTH    3

/*
 * pipeline_pack: writes capture's run fields, createdAt, pubkey (32 B
 * x-only), the tag (tagLen bytes, tagLen must be <= PIPELINE_PACK_MAX_TAG_LEN),
 * and sig into out, at the exact offsets format_descriptor.h describes. out
 * must be at least PIPELINE_FMT_TOTAL_SIZE(tagLen) bytes. Returns the number
 * of bytes written (PIPELINE_FMT_TOTAL_SIZE(tagLen)), or 0 if tagLen exceeds
 * PIPELINE_PACK_MAX_TAG_LEN (a caller bug -- this pipeline's own per-build
 * tag length is a compile-time constant that always satisfies this, so this
 * is a defensive check, not an expected runtime path).
 */
pipeline_u32 pipeline_pack(const StarCapture *capture,
                            pipeline_u32 createdAt,
                            const pipeline_u8 pubkey[PIPELINE_FMT_SIZE_PUBKEY],
                            const pipeline_u8 *tag,
                            pipeline_u8 tagLen,
                            const pipeline_u8 sig[PIPELINE_FMT_SIZE_SIG],
                            pipeline_u8 *out);

/*
 * pipeline_unpack: the inverse of pipeline_pack. in/inLen is the exact
 * decoded byte span (e.g. straight from a QR decoder -- no trailing
 * padding). Writes capture_out, createdAt_out, pubkey_out (32 B),
 * tag_out (up to PIPELINE_PACK_MAX_TAG_LEN bytes, NOT NUL-terminated --
 * tagLen_out says how many are valid), and sig_out on success (return 0).
 * Returns one of the PIPELINE_UNPACK_ERR_* codes above, writing nothing, if
 * FORMAT_TAG != PIPELINE_FMT_TAG_VALUE, TAG_LEN > PIPELINE_PACK_MAX_TAG_LEN,
 * or inLen doesn't exactly equal PIPELINE_FMT_TOTAL_SIZE(the wire TAG_LEN).
 */
int pipeline_unpack(const pipeline_u8 *in,
                     pipeline_u32 inLen,
                     StarCapture *capture_out,
                     pipeline_u32 *createdAt_out,
                     pipeline_u8 pubkey_out[PIPELINE_FMT_SIZE_PUBKEY],
                     pipeline_u8 tag_out[PIPELINE_PACK_MAX_TAG_LEN],
                     pipeline_u8 *tagLen_out,
                     pipeline_u8 sig_out[PIPELINE_FMT_SIZE_SIG]);

#endif /* PIPELINE_PACK_ADAPTER_H */
