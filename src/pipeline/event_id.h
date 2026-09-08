#ifndef PIPELINE_EVENT_ID_H
#define PIPELINE_EVENT_ID_H

/*
 * The canonical NIP-01 serialize + SHA-256 id adapter (spec #24, sub-issue
 * #28) -- the pipeline-internal seam in front of the ported sha256.c
 * (hidden behind this header). Like pack_adapter.h/qr_adapter.h, this file
 * is pure: no MarioState, no globals, no N64 headers. It is compiled a
 * second time, unmodified, into the host test tool (tools/pipeline_test).
 *
 * Scope discipline (spec #24, sub-issue #28): this exposes canonical
 * serialization + id computation as a standalone internal seam, exercised
 * directly by the host test tool's id-equals-reference assertion. It is NOT
 * yet wired into build_event()'s real output -- doing so, plus Schnorr
 * signing (#29) and packing the real payload contents (#30), is later work.
 * Called only from within src/pipeline/ (this file and, in a later
 * sub-issue, build_event.c); game glue never calls this adapter directly.
 *
 * Canonical NIP-01 event id derivation: id = SHA256(serialize(event)), where
 * serialize(event) is the UTF-8, whitespace-free JSON array
 *   [0, <pubkey-hex>, <created_at>, <kind>, <tags>, <content>]
 * with content itself a JSON string -- so when content's own JSON text
 * (built from the StarCapture) is embedded as a *string element* of the
 * outer array, its `"` characters must be escaped to `\"` (the "content
 * double-serialization escaping" path #28's acceptance criteria calls out).
 * pubkey/created_at/kind/tags come from the generated event_profile.h (the
 * "baked serialization prefix" -- constant per build); only content varies
 * per StarCapture.
 *
 * Content shape (fixed key order, matching #28's acceptance criteria):
 *   {"course":<u8>,"act":<u8>,"coins":<u8>,"frames":<u32>,"nonce":<u16>,"keyId":<u8>}
 * keyId (the star index) is part of the SIGNED content, not just the packed
 * wire payload: for stars where `act` alone doesn't identify which star was
 * grabbed (100-coin/secret-course stars) it is load-bearing leaderboard
 * identity, so it must be tamper-evident under the event signature like every
 * other run value (spec #24 user story 1, "no chance to tamper").
 */

#include "build_event.h"

#define PIPELINE_EVENT_ID_SIZE 32

/* Generous fixed upper bound on the content JSON's length (unescaped):
 * literal/key overhead (`{"course":`=10, `,"act":`=7, `,"coins":`=9,
 * `,"frames":`=10, `,"nonce":`=9, `,"keyId":`=9, `}`=1) is 55 bytes, plus up
 * to 3+3+3+10+5+3 = 27 decimal digits for course/act/coins (u8, max 3 digits
 * each), frames (u32, max 10 digits), nonce (u16, max 5 digits), and keyId
 * (u8, max 3 digits) = 82 bytes total, plus 1 for the NUL terminator
 * pipeline_event_build_content() writes. Rounded up with margin. */
#define PIPELINE_EVENT_CONTENT_MAX 128

/* Generous fixed upper bound on the full canonical serialization's length:
 * `[0,"` + 64-hex-char pubkey + `",` + up to 10 digits created_at + `,` +
 * up to 5 digits kind + `,[["t","cabinet-leaderboard"],["t","sm64"]],"` +
 * the escaped content (worst case: every content byte is a quote, doubling
 * PIPELINE_EVENT_CONTENT_MAX) + `"]`. Rounded up with margin. */
#define PIPELINE_EVENT_SERIALIZED_MAX 512

/*
 * pipeline_event_build_content: writes the canonical content JSON for
 * capture into out (NUL-terminated). out must be at least
 * PIPELINE_EVENT_CONTENT_MAX bytes. Returns the length written, excluding
 * the NUL terminator.
 */
pipeline_u32 pipeline_event_build_content(const StarCapture *capture, char out[PIPELINE_EVENT_CONTENT_MAX]);

/*
 * pipeline_event_serialize: writes the full canonical NIP-01 serialization
 * (the baked event-profile prefix plus capture's escaped content) into out.
 * out must be at least PIPELINE_EVENT_SERIALIZED_MAX bytes. Returns the
 * length written (out is not NUL-terminated beyond that length).
 */
pipeline_u32 pipeline_event_serialize(const StarCapture *capture, pipeline_u8 out[PIPELINE_EVENT_SERIALIZED_MAX]);

/*
 * pipeline_event_compute_id: id_out = SHA256(pipeline_event_serialize(capture)).
 */
void pipeline_event_compute_id(const StarCapture *capture, pipeline_u8 id_out[PIPELINE_EVENT_ID_SIZE]);

#endif /* PIPELINE_EVENT_ID_H */
