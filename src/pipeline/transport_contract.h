#ifndef PIPELINE_TRANSPORT_CONTRACT_H
#define PIPELINE_TRANSPORT_CONTRACT_H

/*
 * ADR-0006's adaptive multi-frame airgap transport envelope, realigned to
 * #101's ratified URL schema by spec #122 (sub-issue #123): the single
 * shared source of truth for the base32 alphabet, the fragment header
 * layout, and the URL template pieces every cabinet-side module below
 * derives from -- base32.h/.c, fragment.h/.c, url.h/.c, and
 * build_event.c's frame-emission loop -- so none of them can hand-duplicate
 * a literal that silently drifts from another, the same anti-drift
 * discipline format_descriptor.json gives the packed payload
 * (docs/adr/0006-adaptive-multi-frame-transport-page-reassembles.md).
 * Ticket #119/#123's reader page is the other half of this same contract:
 * it must independently port these exact values (it is JavaScript, not a
 * second includer of this header), but every value it needs to agree on is
 * pinned in exactly one place here.
 *
 * The ratified per-frame URL template is `<BASE>#<SEQ>/<TOTAL>/<PAYLOAD>`
 * (spec #122): `<BASE>` is the provisioned build-time base URL (scheme +
 * host + any path), emitted VERBATIM (never uppercased or otherwise
 * mangled); `#` (PIPELINE_URL_FRAGMENT_SEP) joins it to the fragment, a URL
 * hash fragment a browser never sends to the server; `<SEQ>`, `<TOTAL>`,
 * and `<PAYLOAD>` are `/`-delimited (PIPELINE_URL_FIELD_SEP) inside the
 * fragment. This retires the earlier path-based, all-uppercase,
 * concatenated-header shape spec #115/#116 built (see this header's own
 * git history) -- that shape traced to a stale line of ADR-0006 body prose
 * the ADR itself defers to #101 for.
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
 * Fragment field separator: `/`, joining <SEQ>/<TOTAL>/<PAYLOAD> inside the
 * URL hash fragment (spec #122's ratified template) -- legible, and
 * inside the QR alphanumeric charset, exactly like the base36/base32
 * charsets it separates.
 */
#define PIPELINE_URL_FIELD_SEP "/"
#define PIPELINE_URL_FIELD_SEP_LEN (sizeof(PIPELINE_URL_FIELD_SEP) - 1)

/*
 * Fragment header: PIPELINE_FRAGMENT_INDEX_LEN base36 digits (0-9A-Z) for
 * the 0-based frame index, PIPELINE_URL_FIELD_SEP, then
 * PIPELINE_FRAGMENT_COUNT_LEN base36 digits for the (1-based) total frame
 * count, then another PIPELINE_URL_FIELD_SEP -- e.g. "00/02/" ahead of the
 * base32 chunk -- both index/count fields uppercase alnum, so the whole
 * header rides the exact same QR alphanumeric charset as the base32 chunk
 * that follows it. 2 digits each gives headroom to 36*36 - 1 = 1295 frames,
 * far past ADR-0006's own ~8-10-frame fountain-coding criterion (sequential
 * cycling is expected to stay well under that for the honest floor).
 */
#define PIPELINE_FRAGMENT_BASE36_ALPHABET "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define PIPELINE_FRAGMENT_BASE36_LEN 36
#define PIPELINE_FRAGMENT_INDEX_LEN 2
#define PIPELINE_FRAGMENT_COUNT_LEN 2
#define PIPELINE_FRAGMENT_HEADER_LEN \
    (PIPELINE_FRAGMENT_INDEX_LEN + PIPELINE_URL_FIELD_SEP_LEN + \
     PIPELINE_FRAGMENT_COUNT_LEN + PIPELINE_URL_FIELD_SEP_LEN)
/* The count field stores the actual (1-based) count value, not count-1, so
 * the largest count 2 base36 digits can hold is 36*36 - 1 = 1295 (a value
 * of 1296 would wrap to "00" when base36-encoded -- see fragment.c's
 * encode_base36_field()) -- matching this macro's own name (a MAX, not a
 * digit-count) and this header's own comment above. */
#define PIPELINE_FRAGMENT_MAX_COUNT (PIPELINE_FRAGMENT_BASE36_LEN * PIPELINE_FRAGMENT_BASE36_LEN - 1)

/*
 * URL template (spec #122, #101's ratified schema): <BASE>#<SEQ>/<TOTAL>/<PAYLOAD>.
 * `#` (a URL hash fragment, never sent to the server by a browser) joins
 * the base URL to the fragment -- replacing the earlier `/` path join.
 * <BASE> is a build-time constant (PIPELINE_URL_BASE, generated into
 * event_profile.h mirroring PIPELINE_EVENT_NAME's own provisioning -- see
 * that header's own comment), emitted VERBATIM by url.h's
 * pipeline_url_wrap(): never uppercased, never otherwise mangled, so a
 * case-sensitive host path (e.g. a GitHub Pages project site's lowercase
 * `/repo/`) resolves correctly. Because <BASE> can legally contain
 * lowercase letters and other bytes outside the QR alphanumeric charset,
 * every frame's <BASE># prefix rides a QR BYTE segment; only the
 * `/`-delimited SEQ/TOTAL/PAYLOAD tail rides ALPHANUMERIC (qr_adapter.h's
 * pipeline_qr_encode_two_segment()).
 */
#define PIPELINE_URL_FRAGMENT_SEP "#"
#define PIPELINE_URL_FRAGMENT_SEP_LEN (sizeof(PIPELINE_URL_FRAGMENT_SEP) - 1)

#endif /* PIPELINE_TRANSPORT_CONTRACT_H */
