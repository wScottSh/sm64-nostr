#ifndef PIPELINE_TRANSPORT_CONTRACT_H
#define PIPELINE_TRANSPORT_CONTRACT_H

/*
 * ADR-0006's adaptive multi-frame airgap transport envelope (spec #115,
 * sub-issue #116): the single shared source of truth for the base32
 * alphabet, the fragment header layout, and the URL template pieces every
 * cabinet-side module below derives from -- base32.h/.c, fragment.h/.c,
 * url.h/.c, and build_event.c's frame-emission loop -- so none of them can
 * hand-duplicate a literal that silently drifts from another, the same
 * anti-drift discipline format_descriptor.json gives the packed payload
 * (docs/adr/0006-adaptive-multi-frame-transport-page-reassembles.md).
 * Ticket #119's reader page is the other half of this same contract: it
 * must independently port these exact values (it is JavaScript, not a
 * second includer of this header), but every value it needs to agree on is
 * pinned in exactly one place here.
 *
 * Pure macro constants only -- no typedefs, no #includes -- so this file
 * can be #included directly from build_event.h with zero circular-include
 * risk (mirrors format_descriptor.h/event_profile.h's leaf-header role in
 * build_event.h's own comments on why THOSE headers are safe to include
 * directly while pack_adapter.h/qr_adapter.h are not).
 */

/*
 * RFC 4648 section 6 base32 alphabet, uppercase, no padding character: the
 * wire never emits '=' -- the reassembler is length-driven via the
 * fragment header's frame count, not padding (ADR-0006/spec #115's own
 * Implementation Decisions). base32.h/.c's encode/decode both index this
 * exact 32-character string.
 */
#define PIPELINE_BASE32_ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
#define PIPELINE_BASE32_ALPHABET_LEN 32

/*
 * Fragment header: PIPELINE_FRAGMENT_INDEX_LEN base36 digits (0-9A-Z) for
 * the 0-based frame index, then PIPELINE_FRAGMENT_COUNT_LEN base36 digits
 * for the (1-based) total frame count -- both uppercase alnum, so the
 * header rides the exact same QR alphanumeric charset as the base32 chunk
 * that follows it. 2 digits each gives headroom to 36*36 - 1 = 1295 frames,
 * far past ADR-0006's own ~8-10-frame fountain-coding criterion (sequential
 * cycling is expected to stay well under that for the honest floor).
 */
#define PIPELINE_FRAGMENT_BASE36_ALPHABET "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define PIPELINE_FRAGMENT_BASE36_LEN 36
#define PIPELINE_FRAGMENT_INDEX_LEN 2
#define PIPELINE_FRAGMENT_COUNT_LEN 2
#define PIPELINE_FRAGMENT_HEADER_LEN (PIPELINE_FRAGMENT_INDEX_LEN + PIPELINE_FRAGMENT_COUNT_LEN)
/* The count field stores the actual (1-based) count value, not count-1, so
 * the largest count 2 base36 digits can hold is 36*36 - 1 = 1295 (a value
 * of 1296 would wrap to "00" when base36-encoded -- see fragment.c's
 * encode_base36_field()) -- matching this macro's own name (a MAX, not a
 * digit-count) and this header's own comment above. */
#define PIPELINE_FRAGMENT_MAX_COUNT (PIPELINE_FRAGMENT_BASE36_LEN * PIPELINE_FRAGMENT_BASE36_LEN - 1)

/*
 * URL template: HTTPS://<base-url>/<fragment> -- a complete, valid,
 * all-uppercase, path-based https URL (no `?`/`=` query), so every
 * character a stock phone camera reads stays inside the QR alphanumeric
 * charset (A-Z 0-9 space $ % * + - . / :). The base URL itself is a
 * build-time constant (PIPELINE_URL_BASE, generated into event_profile.h
 * mirroring PIPELINE_EVENT_NAME's own provisioning -- see that header's own
 * comment), not part of this fixed template.
 */
#define PIPELINE_URL_SCHEME "HTTPS://"
#define PIPELINE_URL_SCHEME_LEN (sizeof(PIPELINE_URL_SCHEME) - 1)
#define PIPELINE_URL_PATH_SEP "/"
#define PIPELINE_URL_PATH_SEP_LEN (sizeof(PIPELINE_URL_PATH_SEP) - 1)

#endif /* PIPELINE_TRANSPORT_CONTRACT_H */
