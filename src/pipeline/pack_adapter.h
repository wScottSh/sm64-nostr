#ifndef PIPELINE_PACK_ADAPTER_H
#define PIPELINE_PACK_ADAPTER_H

/*
 * The pack/unpack adapters for the packed QR payload (spec #24, sub-issue
 * #26; format v2 self-contained payload, spec #52 sub-issue #54; format v3
 * second variable-length field (NAME), spec #109 sub-issue #110). Both the
 * ROM pack side and the host unpack side derive their field layout from the
 * SAME generated format_descriptor.h (itself rendered from the single JSON
 * source src/pipeline/format_descriptor.json) -- never a hand-duplicated
 * literal.
 *
 * Like build_event.c/port_stub_c99.c, this file is pure: no MarioState, no
 * globals, no N64 headers. It is compiled a second time, unmodified, into
 * the host test tool (tools/pipeline_test).
 *
 * Format v3 packs the whole self-contained event onto the wire: capture's
 * run fields, CREATED_AT (u32 BE unix seconds), PUBKEY (32 B x-only),
 * TAG_LEN + TAG (0..10 ASCII bytes, the per-game `t` tag), NAME_LEN + NAME
 * (0..20 ASCII bytes, raised from 0..15 by spec #91 sub-issue #126, the
 * event-name `n` tag value), and the 64-byte Schnorr signature. `id` is
 * never packed -- the companion recomputes it.
 * TAG and NAME are the two variable-length fields, in that order, so:
 *   - pipeline_pack()'s output length varies with tagLen/nameLen (the
 *     caller's own build-time lengths); out must be at least
 *     PIPELINE_FMT_TOTAL_SIZE(tagLen, nameLen) bytes, and pipeline_pack()
 *     writes exactly that many.
 *   - pipeline_unpack() must be told the ACTUAL decoded byte length (inLen,
 *     e.g. from the QR decoder), since there is no fixed total size to
 *     assume -- it reads TAG_LEN then NAME_LEN off the wire (in that
 *     order), validates each against its own max, and validates inLen
 *     against PIPELINE_FMT_TOTAL_SIZE(that TAG_LEN, that NAME_LEN) before
 *     trusting anything past that point. in/tagOut/nameOut buffers must be
 *     sized to PIPELINE_PACK_MAX_SIZE / PIPELINE_PACK_MAX_TAG_LEN /
 *     PIPELINE_PACK_MAX_NAME_LEN respectively, since an arbitrary (but
 *     format-v3-legal) incoming payload's tag/name can each be up to their
 *     own max.
 */

#include "build_event.h"
#include "format_descriptor.h"

/* Worst-case total payload size (tagLen and nameLen both at their max) --
 * the right buffer bound for host-side decode/scratch buffers that must
 * hold any legal incoming v3 payload, since an unpack caller doesn't know
 * the incoming tag/name lengths until it has already read TAG_LEN/NAME_LEN
 * off the wire. */
#define PIPELINE_PACK_MAX_SIZE     PIPELINE_FMT_MAX_TOTAL_SIZE
#define PIPELINE_PACK_MAX_TAG_LEN  PIPELINE_FMT_MAX_SIZE_TAG
#define PIPELINE_PACK_MAX_NAME_LEN PIPELINE_FMT_MAX_SIZE_NAME

/*
 * pipeline_unpack()'s return codes: 0 on success, or one of the distinct
 * rejection reasons a conforming decoder must distinguish
 * (docs/qr-handoff-spec.md section 6; format v3, docs/format-v3-spec.md) --
 * FORMAT_TAG mismatch, an over-budget TAG_LEN, an over-budget NAME_LEN, or a
 * total length that doesn't match TAG_LEN/NAME_LEN. Callers should treat
 * ANY nonzero return as "reject, don't guess"; the specific values exist so
 * tests can assert the RIGHT rejection fired.
 */
#define PIPELINE_UNPACK_OK                  0
#define PIPELINE_UNPACK_ERR_BAD_FORMAT_TAG  1
#define PIPELINE_UNPACK_ERR_TAG_TOO_LONG    2
#define PIPELINE_UNPACK_ERR_WRONG_LENGTH    3
#define PIPELINE_UNPACK_ERR_NAME_TOO_LONG   4

/*
 * pipeline_pack: writes capture's run fields, createdAt, pubkey (32 B
 * x-only), the tag (tagLen bytes, tagLen must be <= PIPELINE_PACK_MAX_TAG_LEN),
 * the name (nameLen bytes, nameLen must be <= PIPELINE_PACK_MAX_NAME_LEN),
 * and sig into out, at the exact offsets format_descriptor.h describes. out
 * must be at least PIPELINE_FMT_TOTAL_SIZE(tagLen, nameLen) bytes. Returns
 * the number of bytes written (PIPELINE_FMT_TOTAL_SIZE(tagLen, nameLen)), or
 * 0 if tagLen exceeds PIPELINE_PACK_MAX_TAG_LEN or nameLen exceeds
 * PIPELINE_PACK_MAX_NAME_LEN (a caller bug -- this pipeline's own per-build
 * tag/name lengths are compile-time constants that always satisfy this, so
 * this is a defensive check, not an expected runtime path).
 */
pipeline_u32 pipeline_pack(const StarCapture *capture,
                            pipeline_u32 createdAt,
                            const pipeline_u8 pubkey[PIPELINE_FMT_SIZE_PUBKEY],
                            const pipeline_u8 *tag,
                            pipeline_u8 tagLen,
                            const pipeline_u8 *name,
                            pipeline_u8 nameLen,
                            const pipeline_u8 sig[PIPELINE_FMT_SIZE_SIG],
                            pipeline_u8 *out);

/*
 * pipeline_unpack: the inverse of pipeline_pack. in/inLen is the exact
 * decoded byte span (e.g. straight from a QR decoder -- no trailing
 * padding). Writes capture_out, createdAt_out, pubkey_out (32 B),
 * tag_out (up to PIPELINE_PACK_MAX_TAG_LEN bytes, NOT NUL-terminated --
 * tagLen_out says how many are valid), name_out (up to
 * PIPELINE_PACK_MAX_NAME_LEN bytes, NOT NUL-terminated -- nameLen_out says
 * how many are valid), and sig_out on success (return 0). Returns one of
 * the PIPELINE_UNPACK_ERR_* codes above, writing nothing, if FORMAT_TAG !=
 * PIPELINE_FMT_TAG_VALUE, TAG_LEN > PIPELINE_PACK_MAX_TAG_LEN, NAME_LEN >
 * PIPELINE_PACK_MAX_NAME_LEN, or inLen doesn't exactly equal
 * PIPELINE_FMT_TOTAL_SIZE(the wire TAG_LEN, the wire NAME_LEN). In
 * particular, a payload whose FORMAT_TAG is the old format v2 value (0x02)
 * is rejected here (PIPELINE_UNPACK_ERR_BAD_FORMAT_TAG), never silently
 * misread as v3.
 */
int pipeline_unpack(const pipeline_u8 *in,
                     pipeline_u32 inLen,
                     StarCapture *capture_out,
                     pipeline_u32 *createdAt_out,
                     pipeline_u8 pubkey_out[PIPELINE_FMT_SIZE_PUBKEY],
                     pipeline_u8 tag_out[PIPELINE_PACK_MAX_TAG_LEN],
                     pipeline_u8 *tagLen_out,
                     pipeline_u8 name_out[PIPELINE_PACK_MAX_NAME_LEN],
                     pipeline_u8 *nameLen_out,
                     pipeline_u8 sig_out[PIPELINE_FMT_SIZE_SIG]);

#endif /* PIPELINE_PACK_ADAPTER_H */
