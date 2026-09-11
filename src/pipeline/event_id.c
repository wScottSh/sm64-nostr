/*
 * See event_id.h. Fields are written one byte/one escaped-run at a time at
 * explicitly-computed offsets, never via snprintf/memcpy (both need headers
 * unavailable under the ROM build's -nostdinc -- see build_event.h), the
 * same explicit-serialization discipline pack_adapter.c documents.
 *
 * All append_* helpers below take an explicit `cap` (the destination
 * buffer's total size) and silently stop writing once offset reaches it,
 * never writing past out[cap - 1]. out is always one of the two fixed
 * stack buffers declared in this file's own callers/pipeline_event_compute_id
 * (sized PIPELINE_EVENT_CONTENT_MAX / PIPELINE_EVENT_SERIALIZED_MAX), so
 * this is a defense-in-depth bound against a future change to the baked
 * event-profile strings (pubkey hex, tag values) growing past the
 * documented worst case in event_id.h, not something expected to trigger
 * today -- a clean truncation (wrong id, computed safely) beats a stack
 * buffer overrun.
 */

#include "event_id.h"
#include "event_profile.h"
#include "sha256.h"

/* Compile-time check that the three-tag shape hardcoded into
 * pipeline_event_serialize() below still matches the generated event
 * profile's own tag count. If event_profile.h.in ever grows/shrinks the
 * tag list, this line fails to compile (negative array size) instead of
 * silently serializing a mismatched event. Format v3 (spec #109, sub-issue
 * #111) adds the third tag, ["n","<EVENT NAME>"], carrying the promoted
 * PIPELINE_EVENT_NAME onto the signed serialization -- see
 * pipeline_event_serialize_from_fields()'s own comment below. */
typedef char pipeline_event_id_tag_count_check[(PIPELINE_EVENT_TAG_COUNT == 3) ? 1 : -1];

static pipeline_u32 append_str(pipeline_u8 *out, pipeline_u32 offset, pipeline_u32 cap, const char *s)
{
    while (*s != '\0' && offset < cap) {
        out[offset++] = (pipeline_u8)*s++;
    }
    return offset;
}

/* Appends s with JSON string escaping applied (the `"` -> `\"` case is the
 * one #28's acceptance criteria calls out -- content's own JSON text is
 * embedded as a string element of the outer serialized array). The other
 * escapes (\\, \n, \r, \t, \b, \f) are NIP-01's own documented escape set
 * (the same set JSON.stringify produces for these characters); other C0
 * control characters are NOT escaped to \u00XX here (unlike strict RFC 8259
 * string encoding) since NIP-01 doesn't require it and none of today's
 * purely-numeric content values can ever produce one. */
static pipeline_u32 append_json_escaped(pipeline_u8 *out, pipeline_u32 offset, pipeline_u32 cap, const char *s)
{
    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '"':  offset = append_str(out, offset, cap, "\\\""); break;
            case '\\': offset = append_str(out, offset, cap, "\\\\"); break;
            case '\n': offset = append_str(out, offset, cap, "\\n"); break;
            case '\r': offset = append_str(out, offset, cap, "\\r"); break;
            case '\t': offset = append_str(out, offset, cap, "\\t"); break;
            case '\b': offset = append_str(out, offset, cap, "\\b"); break;
            case '\f': offset = append_str(out, offset, cap, "\\f"); break;
            default:
                if (offset < cap) {
                    out[offset++] = (pipeline_u8)c;
                }
        }
    }
    return offset;
}

/* Appends value as decimal digits, no leading zeros (NIP-01's "shortest
 * numeric representation" rule) -- the same rule JSON.stringify follows for
 * plain (non-fractional, non-negative) integers. */
static pipeline_u32 append_udec(pipeline_u8 *out, pipeline_u32 offset, pipeline_u32 cap, pipeline_u32 value)
{
    char digits[10];
    int n = 0;

    if (value == 0) {
        if (offset < cap) {
            out[offset++] = '0';
        }
        return offset;
    }
    while (value > 0) {
        digits[n++] = (char)('0' + (value % 10));
        value /= 10;
    }
    while (n > 0) {
        if (offset < cap) {
            out[offset++] = (pipeline_u8)digits[--n];
        } else {
            break;
        }
    }
    return offset;
}

pipeline_u32 pipeline_event_build_content(const StarCapture *capture, char out[PIPELINE_EVENT_CONTENT_MAX])
{
    pipeline_u8 *o = (pipeline_u8 *)out;
    /* Reserve the last byte for the NUL terminator written below. */
    pipeline_u32 cap = PIPELINE_EVENT_CONTENT_MAX - 1;
    pipeline_u32 offset = 0;

    offset = append_str(o, offset, cap, "{\"course\":");
    offset = append_udec(o, offset, cap, capture->course);
    offset = append_str(o, offset, cap, ",\"act\":");
    offset = append_udec(o, offset, cap, capture->act);
    offset = append_str(o, offset, cap, ",\"coins\":");
    offset = append_udec(o, offset, cap, capture->coins);
    offset = append_str(o, offset, cap, ",\"frames\":");
    offset = append_udec(o, offset, cap, capture->frames);
    offset = append_str(o, offset, cap, ",\"nonce\":");
    offset = append_udec(o, offset, cap, capture->nonce16);
    offset = append_str(o, offset, cap, ",\"keyId\":");
    offset = append_udec(o, offset, cap, capture->keyId);
    offset = append_str(o, offset, cap, "}");
    out[offset] = '\0';

    return offset;
}

/* Appends the lowercase hex encoding of bytes[0:len). Used for pubkey,
 * which format v2 carries as raw wire bytes (never a pre-baked hex string)
 * when reconstructing generically -- see pipeline_event_serialize_from_fields
 * below. */
static pipeline_u32 append_hex_bytes(pipeline_u8 *out, pipeline_u32 offset, pipeline_u32 cap,
                                      const pipeline_u8 *bytes, pipeline_u32 len)
{
    static const char kHexDigits[] = "0123456789abcdef";
    pipeline_u32 i;

    for (i = 0; i < len; i++) {
        if (offset < cap) {
            out[offset++] = (pipeline_u8)kHexDigits[(bytes[i] >> 4) & 0xF];
        }
        if (offset < cap) {
            out[offset++] = (pipeline_u8)kHexDigits[bytes[i] & 0xF];
        }
    }
    return offset;
}

pipeline_u32 pipeline_event_serialize_from_fields(const pipeline_u8 pubkey[PIPELINE_FMT_SIZE_PUBKEY],
                                                   pipeline_u32 createdAt,
                                                   const char *tag1,
                                                   pipeline_u32 tag1Len,
                                                   const char *name,
                                                   pipeline_u32 nameLen,
                                                   const StarCapture *capture,
                                                   pipeline_u8 out[PIPELINE_EVENT_SERIALIZED_MAX])
{
    char content[PIPELINE_EVENT_CONTENT_MAX];
    pipeline_u32 cap = PIPELINE_EVENT_SERIALIZED_MAX;
    pipeline_u32 offset = 0;
    pipeline_u32 i;

    pipeline_event_build_content(capture, content);

    offset = append_str(out, offset, cap, "[0,\"");
    offset = append_hex_bytes(out, offset, cap, pubkey, PIPELINE_FMT_SIZE_PUBKEY);
    offset = append_str(out, offset, cap, "\",");
    offset = append_udec(out, offset, cap, createdAt);
    offset = append_str(out, offset, cap, ",");
    offset = append_udec(out, offset, cap, (pipeline_u32)PIPELINE_EVENT_KIND);
    /* TAG_0 is always the wire-format-pinned (identical across v2 and v3)
     * constant PIPELINE_EVENT_TAG0_VALUE
     * ("ag-lb", never a parameter -- see this function's header comment in
     * event_id.h and PIPELINE_EVENT_KIND/PIPELINE_EVENT_TAG_KEY/
     * PIPELINE_EVENT_TAG0_VALUE's own definitions there, the single source
     * for these spec-pinned constants). */
    offset = append_str(out, offset, cap,
        ",[[\"" PIPELINE_EVENT_TAG_KEY "\",\"" PIPELINE_EVENT_TAG0_VALUE "\"],[\"" PIPELINE_EVENT_TAG_KEY "\",\"");
    for (i = 0; i < tag1Len; i++) {
        if (offset < cap) {
            out[offset++] = (pipeline_u8)tag1[i];
        }
    }
    /* Third tag, ["n","<EVENT NAME>"] (format v3, spec #109 sub-issue #111):
     * the promoted PIPELINE_EVENT_NAME, appended in canonical position right
     * after the two "t" tags, so it rides the hashed serialization -- the
     * signed `id` now commits to the event name, retiring the old
     * display-only contract. name is written raw, not JSON-escaped: its
     * charset is fixed to A-Z/0-9/space (gen_event_profile.py's
     * normalize_event_name(), unchanged by this sub-issue), which contains
     * no byte that needs JSON string escaping -- the same reasoning tag1
     * above already relies on for its own charset. */
    offset = append_str(out, offset, cap, "\"],[\"" PIPELINE_EVENT_NAME_TAG_KEY "\",\"");
    for (i = 0; i < nameLen; i++) {
        if (offset < cap) {
            out[offset++] = (pipeline_u8)name[i];
        }
    }
    offset = append_str(out, offset, cap, "\"]],\"");
    offset = append_json_escaped(out, offset, cap, content);
    offset = append_str(out, offset, cap, "\"]");

    return offset;
}

void pipeline_event_compute_id_from_fields(const pipeline_u8 pubkey[PIPELINE_FMT_SIZE_PUBKEY],
                                            pipeline_u32 createdAt,
                                            const char *tag1,
                                            pipeline_u32 tag1Len,
                                            const char *name,
                                            pipeline_u32 nameLen,
                                            const StarCapture *capture,
                                            pipeline_u8 id_out[PIPELINE_EVENT_ID_SIZE])
{
    pipeline_u8 buf[PIPELINE_EVENT_SERIALIZED_MAX];
    pipeline_u32 len = pipeline_event_serialize_from_fields(pubkey, createdAt, tag1, tag1Len, name, nameLen,
                                                             capture, buf);

    pipeline_sha256(buf, len, id_out);
}

pipeline_u32 pipeline_event_serialize(const StarCapture *capture, pipeline_u8 out[PIPELINE_EVENT_SERIALIZED_MAX])
{
    static const pipeline_u8 kPubkeyBytes[PIPELINE_FMT_SIZE_PUBKEY] = PIPELINE_EVENT_PUBKEY_BYTES;

    return pipeline_event_serialize_from_fields(kPubkeyBytes, (pipeline_u32)PIPELINE_EVENT_CREATED_AT,
                                                 PIPELINE_EVENT_TAG_1_VALUE,
                                                 (pipeline_u32)PIPELINE_EVENT_TAG_1_LEN,
                                                 PIPELINE_EVENT_NAME,
                                                 (pipeline_u32)PIPELINE_EVENT_NAME_LEN,
                                                 capture, out);
}

void pipeline_event_compute_id(const StarCapture *capture, pipeline_u8 id_out[PIPELINE_EVENT_ID_SIZE])
{
    pipeline_u8 buf[PIPELINE_EVENT_SERIALIZED_MAX];
    pipeline_u32 len = pipeline_event_serialize(capture, buf);

    pipeline_sha256(buf, len, id_out);
}
