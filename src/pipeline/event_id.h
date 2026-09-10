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
 *
 * Format v2 (spec #52, sub-issue #54): pipeline_event_serialize_from_fields()/
 * pipeline_event_compute_id_from_fields() below are the GENERIC forms --
 * they take pubkey/created_at/the per-game tag as plain arguments rather
 * than reading event_profile.h's baked macros, so a caller reconstructing
 * an event purely from UNPACKED WIRE FIELDS (the reader's job -- see
 * docs/qr-handoff-spec.md) can recompute the exact same id with ZERO
 * out-of-band constants -- including `kind` and TAG_0, which is why
 * PIPELINE_EVENT_KIND/PIPELINE_EVENT_TAG_KEY/PIPELINE_EVENT_TAG0_VALUE
 * below are defined HERE (this file), not in event_profile.h.in: they are
 * wire-format-pinned spec constants (docs/qr-handoff-spec.md section 3;
 * identical across format v2 and v3 -- unchanged when v3 landed, spec #109),
 * identical for every build and every caller, never per-build baked data
 * and never a function parameter -- only TAG_1 (the per-game tag) varies
 * per build and is a parameter. event_profile.h.in's own PIPELINE_EVENT_KIND
 * (pre-v2) was a hand-duplicated copy of this same constant; it has been
 * removed from there so there is exactly one definition. pipeline_event_
 * serialize()/pipeline_event_compute_id() (this build's own baked-profile
 * convenience wrappers, in event_id.c) call these generic forms with
 * PIPELINE_EVENT_PUBKEY_BYTES/CREATED_AT/TAG_1_VALUE from event_profile.h
 * -- one implementation, not two that could drift.
 */

#include "build_event.h"

#define PIPELINE_EVENT_ID_SIZE 32

/* Wire-format-pinned spec constants (docs/qr-handoff-spec.md section 3;
 * identical across format v2 and v3): `kind` and the FIRST tag
 * (`["t","ag-lb"]`) are fixed for every build --
 * part of the published wire-format standard, never baked per-build data
 * and never packed onto the wire (the reader already knows them from
 * the spec, the moment it sees FORMAT_TAG -- 0x03 as of format v3, spec
 * #109/sub-issue #110). The per-game SECOND tag
 * (event_profile.h's PIPELINE_EVENT_TAG_1_VALUE) and the THIRD tag's VALUE
 * (event_profile.h's PIPELINE_EVENT_NAME, format v3 spec #109 sub-issue
 * #111) are the two tag values that vary per build -- PIPELINE_EVENT_
 * NAME_TAG_KEY below ("n") is itself still a format-v3-pinned spec
 * constant (docs/format-v3-spec.md, ADR-0007), never baked per-build data,
 * exactly like PIPELINE_EVENT_TAG_KEY/PIPELINE_EVENT_TAG0_VALUE. */
#define PIPELINE_EVENT_KIND          8064
#define PIPELINE_EVENT_TAG_KEY       "t"
#define PIPELINE_EVENT_TAG0_VALUE    "ag-lb"
/* The third tag's KEY (format v3, spec #109 sub-issue #111) -- ["n",<name>],
 * see pipeline_event_serialize_from_fields()'s own comment below. Only the
 * VALUE (the baked event name) varies per build; the key itself is pinned. */
#define PIPELINE_EVENT_NAME_TAG_KEY  "n"

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
 * up to 5 digits kind + `,[["t","ag-lb"],["t","` + up to 10 tag bytes
 * (format v2's PIPELINE_FMT_MAX_SIZE_TAG) + `"],["n","` + up to 15 name
 * bytes (format v3's PIPELINE_FMT_MAX_SIZE_NAME, spec #109 sub-issue #111)
 * + `"]],"` + the escaped content (worst case: every content byte is a
 * quote, doubling PIPELINE_EVENT_CONTENT_MAX) + `"]`. Rounded up with
 * margin. */
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

/*
 * pipeline_event_serialize_from_fields: the generic form of
 * pipeline_event_serialize() -- pubkey (32 raw bytes, hex-encoded here),
 * createdAt, tag1/tag1Len (the per-game tag, NOT NUL-terminated), and
 * name/nameLen (the event name, NOT NUL-terminated; format v3, spec #109
 * sub-issue #111) are plain arguments instead of event_profile.h's baked
 * macros, so a caller with only unpacked wire fields (no access to -- or
 * need of -- this build's own event_profile.h) can still produce the exact
 * canonical serialization. TAG_0 is always the format-v2-pinned literal
 * "ag-lb" (see this file's header comment); it is not a parameter. The tags
 * array is `[["t",TAG_0],["t",tag1],["n",name]]` -- name is appended in
 * canonical position after both "t" tags, so the signed `id` commits to it.
 * out must be at least PIPELINE_EVENT_SERIALIZED_MAX bytes. Returns the
 * length written.
 */
pipeline_u32 pipeline_event_serialize_from_fields(const pipeline_u8 pubkey[PIPELINE_FMT_SIZE_PUBKEY],
                                                   pipeline_u32 createdAt,
                                                   const char *tag1,
                                                   pipeline_u32 tag1Len,
                                                   const char *name,
                                                   pipeline_u32 nameLen,
                                                   const StarCapture *capture,
                                                   pipeline_u8 out[PIPELINE_EVENT_SERIALIZED_MAX]);

/*
 * pipeline_event_compute_id_from_fields: id_out =
 * SHA256(pipeline_event_serialize_from_fields(...)). See that function's
 * comment -- this is the "reconstruct purely from unpacked wire fields"
 * entry point a companion decoder's equivalent logic mirrors.
 */
void pipeline_event_compute_id_from_fields(const pipeline_u8 pubkey[PIPELINE_FMT_SIZE_PUBKEY],
                                            pipeline_u32 createdAt,
                                            const char *tag1,
                                            pipeline_u32 tag1Len,
                                            const char *name,
                                            pipeline_u32 nameLen,
                                            const StarCapture *capture,
                                            pipeline_u8 id_out[PIPELINE_EVENT_ID_SIZE]);

#endif /* PIPELINE_EVENT_ID_H */
