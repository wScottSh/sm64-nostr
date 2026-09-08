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

/* Compile-time check that the two-tag shape hardcoded into
 * pipeline_event_serialize() below still matches the generated event
 * profile's own tag count. If event_profile.h.in ever grows/shrinks the
 * tag list, this line fails to compile (negative array size) instead of
 * silently serializing a mismatched event. */
typedef char pipeline_event_id_tag_count_check[(PIPELINE_EVENT_TAG_COUNT == 2) ? 1 : -1];

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
    offset = append_str(o, offset, cap, "}");
    out[offset] = '\0';

    return offset;
}

pipeline_u32 pipeline_event_serialize(const StarCapture *capture, pipeline_u8 out[PIPELINE_EVENT_SERIALIZED_MAX])
{
    char content[PIPELINE_EVENT_CONTENT_MAX];
    pipeline_u32 cap = PIPELINE_EVENT_SERIALIZED_MAX;
    pipeline_u32 offset = 0;

    pipeline_event_build_content(capture, content);

    offset = append_str(out, offset, cap, "[0,\"");
    offset = append_str(out, offset, cap, PIPELINE_EVENT_PUBKEY_HEX);
    offset = append_str(out, offset, cap, "\",");
    offset = append_udec(out, offset, cap, (pipeline_u32)PIPELINE_EVENT_CREATED_AT);
    offset = append_str(out, offset, cap, ",");
    offset = append_udec(out, offset, cap, (pipeline_u32)PIPELINE_EVENT_KIND);
    offset = append_str(out, offset, cap,
        ",[[\"" PIPELINE_EVENT_TAG_0_KEY "\",\"" PIPELINE_EVENT_TAG_0_VALUE "\"],"
        "[\"" PIPELINE_EVENT_TAG_1_KEY "\",\"" PIPELINE_EVENT_TAG_1_VALUE "\"]],\"");
    offset = append_json_escaped(out, offset, cap, content);
    offset = append_str(out, offset, cap, "\"]");

    return offset;
}

void pipeline_event_compute_id(const StarCapture *capture, pipeline_u8 id_out[PIPELINE_EVENT_ID_SIZE])
{
    pipeline_u8 buf[PIPELINE_EVENT_SERIALIZED_MAX];
    pipeline_u32 len = pipeline_event_serialize(capture, buf);

    pipeline_sha256(buf, len, id_out);
}
