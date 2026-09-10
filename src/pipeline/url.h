#ifndef PIPELINE_URL_H
#define PIPELINE_URL_H

/*
 * The URL wrapper (ADR-0006's airgap transport, spec #115 sub-issue #116):
 * a pure, pipeline-internal seam wrapping a fragment (fragment.h's header +
 * base32 chunk) as a complete, valid, all-uppercase, path-based `https://`
 * URL -- `HTTPS://<base-url>/<fragment>` -- so a stock phone camera can
 * open ANY single emitted frame into the airgap-jumper page (ticket #119).
 * Like base32.h/.c/fragment.h/.c, this file is pure C89, compiled a second
 * time, unmodified, into the host test tool (tools/pipeline_test).
 *
 * The scheme/path-separator pieces of the template are transport_contract.h's
 * fixed constants; the base URL itself is a build-time constant
 * (PIPELINE_URL_BASE, generated into event_profile.h mirroring
 * PIPELINE_EVENT_NAME's own provisioning) supplied by the caller
 * (build_event.c), never hand-duplicated here.
 */

#include "build_event.h"
#include "transport_contract.h"

/*
 * pipeline_url_wrap: writes PIPELINE_URL_SCHEME + baseUrl[0 : baseUrlLen] +
 * PIPELINE_URL_PATH_SEP + fragment[0 : fragmentLen] into out. out must be
 * at least PIPELINE_URL_SCHEME_LEN + baseUrlLen + PIPELINE_URL_PATH_SEP_LEN
 * + fragmentLen bytes (outCap is that bound, checked defensively). Returns
 * the number of bytes written on success. Returns 0 -- writing nothing --
 * if outCap is too small. Does not case-fold or otherwise validate
 * baseUrl/fragment: callers are responsible for supplying already-uppercase,
 * already-alphanumeric-charset text (build_event.c's baseUrl comes from the
 * already-validated PIPELINE_URL_BASE; fragment comes from fragment.h's
 * own uppercase base36 header + base32.h's own uppercase alphabet).
 */
pipeline_u32 pipeline_url_wrap(const pipeline_u8 *baseUrl, pipeline_u32 baseUrlLen,
                                const pipeline_u8 *fragment, pipeline_u32 fragmentLen,
                                pipeline_u8 *out, pipeline_u32 outCap);

/*
 * pipeline_url_strip: the inverse of pipeline_url_wrap for a KNOWN baseUrl
 * (this build's own PIPELINE_URL_BASE; a real reader page, ticket #119,
 * knows its own domain the same way). Verifies url[0 : urlLen] begins with
 * exactly PIPELINE_URL_SCHEME + baseUrl[0 : baseUrlLen] + PIPELINE_URL_PATH_SEP
 * (byte-for-byte), then copies the remainder into fragmentOut. fragmentOut
 * must be at least urlLen bytes (outCap is that bound, checked
 * defensively). Returns nonzero (true) and sets *fragmentLenOut on
 * success. Returns 0 (false) -- writing nothing -- if url is shorter than
 * the expected prefix, the prefix doesn't match byte-for-byte, or outCap
 * is too small for the remainder.
 */
int pipeline_url_strip(const pipeline_u8 *url, pipeline_u32 urlLen,
                        const pipeline_u8 *baseUrl, pipeline_u32 baseUrlLen,
                        pipeline_u8 *fragmentOut, pipeline_u32 outCap, pipeline_u32 *fragmentLenOut);

#endif /* PIPELINE_URL_H */
