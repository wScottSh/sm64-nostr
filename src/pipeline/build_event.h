#ifndef PIPELINE_BUILD_EVENT_H
#define PIPELINE_BUILD_EVENT_H

/*
 * The pipeline's pure interface: build_event(StarCapture, key) -> BuiltEvent.
 * See spec #24 / sub-issue #25 (walking skeleton) and sub-issue #30 (real
 * interface: this is where the serialize -> SHA-256 id -> Schnorr sign ->
 * pack -> QR encode chain is actually wired together).
 *
 * This module must never include MarioState, game globals, or any N64
 * header -- it is compiled twice, unmodified, into both the ROM build and
 * the host test tool (tools/pipeline_test). It defines its own fixed-width
 * types below instead of depending on <stdint.h> (unavailable under the ROM
 * build's -nostdinc) or the decomp's own N64 types.h.
 *
 * Also pulls in format_descriptor.h for its size macros only
 * (PIPELINE_FMT_FIXED_SIZE, which PIPELINE_BUILT_PAYLOAD_SIZE below is
 * built from) -- the SAME generated, single-source-of-truth constants
 * pack_adapter.h's pipeline_pack()/pipeline_unpack() actually use, never a
 * hand-duplicated literal that could silently drift. Format v2 (spec #52,
 * sub-issue #54) also pulls in event_profile.h for PIPELINE_EVENT_TAG_1_LEN
 * (the per-game tag's compile-time length, itself a sizeof() of a build-
 * time string macro -- see event_profile.h.in): THIS build's own packed
 * payload size is fixed at compile time even though the wire FORMAT
 * supports a variable tag length, because a single ROM build only ever
 * bakes and packs its own one per-game tag. event_profile.h has no
 * circular-include hazard with this file (unlike pack_adapter.h -- see the
 * comment below), so it's included directly.
 *
 * Deliberately included here rather than via pack_adapter.h directly:
 * pack_adapter.h itself #includes "build_event.h" (for StarCapture/
 * pipeline_u8), so if THIS file included pack_adapter.h back, a
 * translation unit that happens to #include "pack_adapter.h" FIRST would
 * open PIPELINE_PACK_ADAPTER_H's own include guard, then reach its nested
 * #include "build_event.h" -- which proceeds normally (this file's own
 * guard, PIPELINE_BUILD_EVENT_H, isn't set yet) and, partway through,
 * reaches THIS #include "pack_adapter.h" line -- which DOES no-op, because
 * PIPELINE_PACK_ADAPTER_H is already open from the outermost include.
 * PIPELINE_PACK_MAX_SIZE (defined later in pack_adapter.h, after that
 * no-op'd include) never gets defined, so referencing it below would be an
 * undeclared-identifier error. format_descriptor.h/event_profile.h have no
 * such cycle (neither includes build_event.h), so going one level lower,
 * straight to the generated headers, avoids the problem entirely.
 */
#include "format_descriptor.h"
#include "event_profile.h"
#include "transport_contract.h"

typedef unsigned char  pipeline_u8;
typedef unsigned short pipeline_u16;
typedef unsigned int   pipeline_u32;

/*
 * Plain-old-data capture of the inputs needed to build a star-grab event.
 * Filled entirely by N64-side capture glue at interact_star_or_key; the
 * pipeline itself never reads course/act globals, MarioState, or timers.
 *
 * Fields are serialized explicitly, one at a time, by the (future) real
 * serialize stage -- never via memcpy/struct-layout -- so host/target
 * struct padding and endianness differences can never leak into the wire
 * format. Don't rely on this struct's in-memory layout for anything.
 */
typedef struct StarCapture {
    pipeline_u8  course;
    pipeline_u8  act;
    pipeline_u8  coins;
    pipeline_u32 frames;
    pipeline_u16 nonce16;
    pipeline_u8  keyId;
} StarCapture;

#define PIPELINE_KEY_SIZE 32

/* This build's own packed payload size: format v3's wire layout supports a
 * variable-length per-game tag (0..10 B) and a variable-length event name
 * (0..17 B, raised 0..15->0..20 B by spec #91 sub-issue #126, then shrunk
 * back 0..20->0..17 B by spec #90 sub-issue #139, which supersedes #126),
 * but any ONE ROM build only ever bakes and packs its own single tag
 * (PIPELINE_EVENT_TAG_1_VALUE) and single event name (PIPELINE_EVENT_
 * NAME), both fixed at compile time (PIPELINE_EVENT_TAG_1_LEN,
 * PIPELINE_EVENT_NAME_LEN) -- so PIPELINE_BUILT_PAYLOAD_SIZE below is itself
 * a fixed compile-time constant for this build, derived from the SAME
 * format_descriptor.h fixed-size accounting (PIPELINE_FMT_FIXED_SIZE)
 * pack_adapter.h's pipeline_pack()/pipeline_unpack() use (via
 * PIPELINE_FMT_TOTAL_SIZE(tagLen, nameLen)), never a hand-duplicated
 * literal. A decoder handling an ARBITRARY incoming payload (a different
 * build's tag/name lengths) must instead use PIPELINE_PACK_MAX_SIZE
 * (pack_adapter.h) and the wire TAG_LEN/NAME_LEN it reads at runtime -- see
 * pipeline_unpack()'s own contract. */
#define PIPELINE_BUILT_PAYLOAD_SIZE (PIPELINE_FMT_FIXED_SIZE + PIPELINE_EVENT_TAG_1_LEN + PIPELINE_EVENT_NAME_LEN)

/*
 * QR bitmap buffer sizing: mirrors qrcodegen_BUFFER_LEN_FOR_VERSION(7) --
 * ((version*4+17)^2 + 7) / 8 + 1 -- from qrcodegen.h/qr_adapter.h's fixed
 * version 7 choice (spec #52, sub-issue #53), WITHOUT #including
 * qrcodegen.h here. qr_adapter.h's own header comment documents that
 * qrcodegen.h/qrcodegen.c must stay hidden behind the qr_adapter.h seam
 * (never visible to callers outside src/pipeline/, including game glue,
 * #31/#32) -- #including it from this file, which every pipeline-internal
 * header transitively pulls in via StarCapture/pipeline_u8, would leak
 * qrcodegen's whole public surface (qrcodegen_encodeBinary, its enums, ...)
 * to every build_event.h consumer. build_event.c's own compile-time checks
 * (comparing PIPELINE_BUILT_QR_VERSION/PIPELINE_BUILT_QR_BITMAP_SIZE
 * against qr_adapter.h's PIPELINE_QR_VERSION/PIPELINE_QR_BUFFER_LEN) are
 * what keep this duplicated formula from silently drifting instead.
 */
#define PIPELINE_BUILT_QR_VERSION 7
#define PIPELINE_BUILT_QR_BITMAP_SIZE \
    ((((PIPELINE_BUILT_QR_VERSION) * 4 + 17) * ((PIPELINE_BUILT_QR_VERSION) * 4 + 17) + 7) / 8 + 1)

/*
 * ADR-0006's adaptive multi-frame airgap transport (spec #115, sub-issue
 * #116): build_event() no longer QR-encodes the packed payload's raw bytes
 * directly. It base32-encodes them (base32.h), splits the base32 text into
 * N URL-wrapped fragments (fragment.h/url.h), and QR-encodes each fragment
 * as a TWO-SEGMENT QR (qr_adapter.h's pipeline_qr_encode_two_segment() --
 * a BYTE segment for the verbatim `<BASE>#` prefix, an ALPHANUMERIC segment
 * for the fragment tail; spec #122, sub-issue #123's realignment to #101's
 * ratified URL schema) -- a reversible ENVELOPE around the exact same
 * packed_payload bytes below, never a new format. Every size in this section
 * is a fixed compile-time
 * constant for THIS build (fixed tag/name lengths, fixed PIPELINE_URL_BASE),
 * exactly like PIPELINE_BUILT_PAYLOAD_SIZE above -- see that macro's own
 * comment for why a decoder handling an ARBITRARY incoming build's frames
 * instead needs runtime-read lengths (fragment.h's own header, parsed by
 * pipeline_fragment_parse_header()).
 *
 * PIPELINE_BUILT_BASE32_LEN duplicates base32.h's own
 * PIPELINE_BASE32_ENCODED_LEN(n) formula (ceil(n*8/5), no padding) rather
 * than #including base32.h here, for the identical circular-include reason
 * PIPELINE_BUILT_QR_BITMAP_SIZE above duplicates qr_adapter.h's buffer-size
 * formula instead of #including THAT header (see this file's own top-of-
 * file comment on the pack_adapter.h hazard: base32.h itself #includes
 * this file, so the reverse #include here would risk the exact same
 * "macro referenced before its nested #include actually defines it"
 * failure mode for a TU that happens to #include base32.h first).
 * build_event.c's own compile-time check
 * (pipeline_build_event_base32_len_check) is what keeps this duplicated
 * formula from silently drifting instead, exactly like the QR-bitmap-size
 * check already does for PIPELINE_BUILT_QR_BITMAP_SIZE.
 */
#define PIPELINE_BUILT_BASE32_LEN (((pipeline_u32)(PIPELINE_BUILT_PAYLOAD_SIZE) * 8u + 4u) / 5u)

/*
 * Data-codeword capacity of a version 7, ECC MEDIUM QR Code: duplicates
 * qr_adapter.h's PIPELINE_QR_DATA_CODEWORDS (124, see that header's own
 * derivation comment) for the identical circular-include reason
 * PIPELINE_BUILT_QR_VERSION/PIPELINE_BUILT_QR_BITMAP_SIZE above duplicate
 * qr_adapter.h's other constants instead of #including it (qr_adapter.h
 * itself #includes this file). build_event.c's own compile-time check
 * (pipeline_build_event_qr_data_codewords_check) keeps the two from
 * silently drifting.
 *
 * Needed here, rather than the older single-segment PIPELINE_QR_ALNUM_MAX_CHARS
 * ceiling (spec #122, sub-issue #123 -- #101's ratified
 * `<BASE>#<SEQ>/<TOTAL>/<PAYLOAD>` template): every frame's URL is now
 * QR-encoded as TWO segments (qr_adapter.h's pipeline_qr_encode_two_segment()) --
 * a BYTE segment for the verbatim `<BASE>#` prefix (which can legally
 * contain lowercase letters and other bytes outside the QR alphanumeric
 * charset) and an ALPHANUMERIC segment for the `/`-delimited
 * SEQ/TOTAL/PAYLOAD fragment tail -- so the per-frame character budget can
 * no longer be expressed purely in ALPHANUMERIC-mode characters; it must
 * instead be derived from the raw data-bit budget the two segments share.
 */
#define PIPELINE_BUILT_QR_DATA_CODEWORDS 124

/* Fixed per-segment bit overhead (4-bit mode indicator + the mode's own
 * character-count field width) at versions 1-9 (this build is pinned to
 * version 7, PIPELINE_BUILT_QR_VERSION above): BYTE mode's 8-bit count,
 * ALPHANUMERIC mode's 9-bit count -- the QR spec's own fixed header widths
 * (qrcodegen.c's numCharCountBits()/alphanumericCharCountBits()), not a
 * value this build derives. Hand-duplicated constants, like every other
 * value in this section -- build_event.c's own compile-time checks
 * (pipeline_build_event_byte_seg_header_bits_check/
 * pipeline_build_event_alnum_seg_header_bits_check) cross-check both
 * against qr_adapter.h's own independently-derived single-segment
 * ceilings (PIPELINE_QR_MAX_PAYLOAD_BYTES/PIPELINE_QR_ALNUM_MAX_CHARS) so
 * neither can silently drift. */
#define PIPELINE_BUILT_BYTE_SEG_HEADER_BITS 12u
#define PIPELINE_BUILT_ALNUM_SEG_HEADER_BITS 13u

/*
 * The build-time base URL every frame's URL wraps a fragment around (spec
 * #115 sub-issue #116, realigned to #101's ratified schema by spec #122
 * sub-issue #123; mirrors PIPELINE_EVENT_NAME's own build-time
 * provisioning, event_profile.h.in's own comment): baked into the
 * generated event_profile.h by gen_event_profile.py's --url-base
 * (Makefile's PIPELINE_URL_BASE, defaulted -- unlike PIPELINE_EVENT_NAME,
 * PIPELINE_URL_BASE is never fail-closed; a dev placeholder host is always
 * a legal build), and emitted VERBATIM -- never uppercased or otherwise
 * mangled (url.h's pipeline_url_wrap()). Deliberately NOT given a second,
 * hand-duplicated #ifndef fallback here: this header already #includes
 * event_profile.h above, so PIPELINE_URL_BASE/PIPELINE_URL_BASE_LEN are
 * always defined by the time this line is reached (the generator template
 * always emits them, unconditionally, exactly like PIPELINE_EVENT_NAME_LEN) --
 * a fallback would silently paper over a stale/hand-edited generated
 * header instead of failing loudly, the opposite of this pipeline's own
 * "loud, not silent" convention.
 */

/* The BYTE segment every frame carries: this build's own verbatim
 * PIPELINE_URL_BASE plus the literal PIPELINE_URL_FRAGMENT_SEP ("#")
 * fragment join -- spec #122's ratified template. */
#define PIPELINE_BUILT_URL_BYTE_SEG_LEN \
    ((pipeline_u32)PIPELINE_URL_BASE_LEN + (pipeline_u32)PIPELINE_URL_FRAGMENT_SEP_LEN)

/* The ALPHANUMERIC-mode raw bit budget left for the SEQ/TOTAL/PAYLOAD
 * fragment tail once both segments' fixed header bits and the BYTE
 * segment's own data bits (8 bits/byte) are subtracted from the QR's total
 * raw data-bit capacity. Signed `long` arithmetic throughout (mirroring
 * this section's own prior discipline) so an over-long PIPELINE_URL_BASE
 * can never wrap an unsigned subtraction into a huge positive value and
 * masquerade as a valid budget. */
#define PIPELINE_BUILT_ALNUM_BUDGET_BITS \
    ((long)(PIPELINE_BUILT_QR_DATA_CODEWORDS) * 8L \
     - (long)PIPELINE_BUILT_BYTE_SEG_HEADER_BITS \
     - 8L * (long)PIPELINE_BUILT_URL_BYTE_SEG_LEN \
     - (long)PIPELINE_BUILT_ALNUM_SEG_HEADER_BITS)

/* ALPHANUMERIC mode packs 2 characters per 11 bits (a lone trailing
 * character costs 6 bits) -- the same packing qrcodegen.c's
 * qrcodegen_encodeAlphanumeric()/qrcodegen_encodeTwoSegments() use.
 * Converts a raw bit budget into the equivalent maximum character count. */
#define PIPELINE_ALNUM_CHARS_FOR_BITS(bits) \
    ((pipeline_u32)(2L * ((bits) / 11L) + (((bits) % 11L) >= 6L ? 1L : 0L)))

/* The exact bits needed to carry PIPELINE_FRAGMENT_HEADER_LEN + 1 alnum
 * characters (the header plus at least one base32 payload character) --
 * computed with the same odd/even packing formula above, never a bare
 * magic-number bit count, so this stays self-consistent with
 * PIPELINE_FRAGMENT_HEADER_LEN's own value if that ever changes. */
#define PIPELINE_BUILT_MIN_ALNUM_BUDGET_BITS \
    (11L * (((long)PIPELINE_FRAGMENT_HEADER_LEN + 1L) / 2L) + \
     ((((long)PIPELINE_FRAGMENT_HEADER_LEN + 1L) % 2L) != 0L ? 6L : 0L))

/* This build's own fixed per-fragment character budget (header + chunk),
 * derived from the shared two-segment bit budget above (spec #122; see
 * this section's own comment for why this is no longer a pure-ALPHANUMERIC
 * character ceiling). build_event.c's own compile-time check
 * (pipeline_build_event_fragment_budget_check) fails loudly, not silently,
 * if a longer PIPELINE_URL_BASE ever leaves no room for even one base32
 * character per fragment. */
#define PIPELINE_BUILT_FRAGMENT_BUDGET \
    PIPELINE_ALNUM_CHARS_FOR_BITS(PIPELINE_BUILT_ALNUM_BUDGET_BITS)
#define PIPELINE_BUILT_FRAGMENT_CHUNK_LEN \
    (PIPELINE_BUILT_FRAGMENT_BUDGET - (pipeline_u32)PIPELINE_FRAGMENT_HEADER_LEN)

/* This build's own fixed frame count: ceil(base32 length / chunk length),
 * minimum 1 (the N=1 case -- a payload whose base32 text fits one frame's
 * budget). A real StarCapture's default "sm64" tag plus a representative
 * (multi-character) event name produces N>=2 here, per spec #115 sub-issue
 * #116's own acceptance criterion; a short-enough tag+name combination
 * (or the host test tool's own short fixture name) stays at N=1. */
#define PIPELINE_BUILT_FRAME_COUNT \
    ((((pipeline_u32)PIPELINE_BUILT_BASE32_LEN) + (PIPELINE_BUILT_FRAGMENT_CHUNK_LEN) - 1u) / \
     (PIPELINE_BUILT_FRAGMENT_CHUNK_LEN))

/* Every frame's full URL text is exactly the BYTE segment
 * (PIPELINE_BUILT_URL_BYTE_SEG_LEN, "<BASE>#") followed by the ALPHANUMERIC
 * fragment (up to PIPELINE_BUILT_FRAGMENT_BUDGET chars) -- the two pieces
 * the per-frame budget above was derived from, so their sum is this
 * build's exact per-frame URL length ceiling. */
#define PIPELINE_BUILT_URL_MAX_LEN \
    ((pipeline_u32)PIPELINE_BUILT_URL_BYTE_SEG_LEN + (pipeline_u32)PIPELINE_BUILT_FRAGMENT_BUDGET)

/*
 * The pipeline's real output (spec #24, sub-issue #30; format v2 self-
 * contained payload, spec #52 sub-issue #54; format v3 NAME_LEN/NAME field,
 * spec #109 sub-issues #110/#111; ADR-0006 multi-frame transport, spec #115
 * sub-issue #116): the packed payload (format tag + StarCapture's fields +
 * CREATED_AT + PUBKEY + TAG_LEN/TAG + NAME_LEN/NAME + 64-byte Schnorr
 * signature, per format_descriptor.json -- PIPELINE_FMT_FIXED_SIZE (113 B)
 * + this build's own tag length + this build's own event-name length,
 * e.g. 121 B for "sm64" and a 4-char event name -- see
 * PIPELINE_BUILT_PAYLOAD_SIZE's own comment above), the frame count, and
 * the N QR bitmaps (one per URL-wrapped fragment, qrcodegen format; read
 * via pipeline_qr_get_size()/pipeline_qr_get_module(), see qr_adapter.h) --
 * replacing format v2/early-v3's single qr_bitmap field. frame_count is
 * always exactly PIPELINE_BUILT_FRAME_COUNT on success; it is carried as
 * an explicit field (rather than a caller having to know that compile-time
 * constant's name) because that is the shape ADR-0006 documents the
 * transport's real output as: "a frame count and a sequence of QR
 * bitmaps".
 */
typedef struct BuiltEvent {
    pipeline_u8 packed_payload[PIPELINE_BUILT_PAYLOAD_SIZE];
    pipeline_u32 frame_count;
    pipeline_u8 qr_bitmaps[PIPELINE_BUILT_FRAME_COUNT][PIPELINE_BUILT_QR_BITMAP_SIZE];
} BuiltEvent;

/*
 * build_event: the pipeline's one interface. Pure and deterministic given
 * (capture, key) -- touches no globals, no timers, no I/O, no MarioState.
 * Chains, internally: canonical NIP-01 serialize + SHA-256 id
 * (event_id.h) -> BIP-340 Schnorr sign of that id with key (schnorr_adapter.h)
 * -> pack capture's fields + the signature into the wire payload
 * (pack_adapter.h) -> QR-encode that payload (qr_adapter.h). capture's
 * nonce16 is an INPUT field (StarCapture), not computed here -- deriving it
 * from capture-time entropy is capture glue's job (#31), out of scope for
 * this pure module.
 *
 * Returns nonzero (true) on success, writing out->packed_payload,
 * out->frame_count (always PIPELINE_BUILT_FRAME_COUNT), and every frame in
 * out->qr_bitmaps[0 : frame_count]. Returns 0 (false) on failure --
 * pipeline_schnorr_sign()'s astronomically-unlikely out-of-range-key/
 * zero-nonce cases (schnorr_adapter.h), in which case out is left entirely
 * untouched; or any internal step past that (pipeline_pack(), base32.h's
 * pipeline_base32_encode(), fragment.h's pipeline_fragment_build(),
 * url.h's pipeline_url_wrap(), or qr_adapter.h's
 * pipeline_qr_encode_two_segment()) reporting a length/budget mismatch --
 * which this build's own compile-time checks in build_event.c (mirroring
 * pipeline_build_event_base32_len_check's existing discipline) already
 * refuse to build at all if the fixed compile-time sizes above ever
 * disagree with the real seams they duplicate, so these are defensive
 * runtime paths, not expected ones. On any such failure,
 * out->packed_payload may already have been written (pipeline_pack() runs
 * first) but the call as a whole must still be treated as failed --
 * callers must check the return value and never treat out as valid
 * otherwise.
 */
int build_event(const StarCapture *capture, const pipeline_u8 key[PIPELINE_KEY_SIZE], BuiltEvent *out);

#endif /* PIPELINE_BUILD_EVENT_H */
