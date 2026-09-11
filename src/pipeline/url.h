#ifndef PIPELINE_URL_H
#define PIPELINE_URL_H

/*
 * The URL wrapper (ADR-0006's airgap transport, realigned to #101's
 * ratified schema by spec #122 sub-issue #123): a pure, pipeline-internal
 * seam wrapping a fragment (fragment.h's `/`-delimited header + base32
 * chunk) as `<BASE>#<fragment>` -- a URL hash fragment join, base emitted
 * VERBATIM -- so a stock phone camera can open ANY single emitted frame
 * into the airgap-jumper page (ticket #119), regardless of which host
 * actually serves that page. Like base32.h/.c/fragment.h/.c, this file is
 * pure C89, compiled a second time, unmodified, into the host test tool
 * (tools/pipeline_test).
 *
 * The `#` join is transport_contract.h's fixed PIPELINE_URL_FRAGMENT_SEP
 * constant; the base URL itself is a build-time constant (PIPELINE_URL_BASE,
 * generated into event_profile.h mirroring PIPELINE_EVENT_NAME's own
 * provisioning) supplied by the caller (build_event.c), never
 * hand-duplicated here, and copied byte-for-byte -- this file never
 * case-folds or otherwise mangles it.
 *
 * Host-agnostic reader (spec #122's own decision): recovering the fragment
 * from a scanned URL never compares the URL's base against any expected
 * value -- pipeline_url_extract_fragment() below takes no baseUrl
 * parameter at all. It is structurally incapable of host coupling.
 */

#include "build_event.h"
#include "transport_contract.h"

/*
 * pipeline_url_wrap: writes baseUrl[0 : baseUrlLen] + PIPELINE_URL_FRAGMENT_SEP
 * + fragment[0 : fragmentLen] into out, VERBATIM (baseUrl's bytes are
 * copied exactly as given -- never uppercased, never otherwise mangled).
 * out must be at least baseUrlLen + PIPELINE_URL_FRAGMENT_SEP_LEN +
 * fragmentLen bytes (outCap is that bound, checked defensively). Returns
 * the number of bytes written on success. Returns 0 -- writing nothing --
 * if outCap is too small. Does not validate fragment's charset: callers
 * are responsible for supplying an already-valid fragment (fragment.h's
 * own uppercase base36 header + `/` field separators + base32.h's own
 * uppercase alphabet).
 */
pipeline_u32 pipeline_url_wrap(const pipeline_u8 *baseUrl, pipeline_u32 baseUrlLen,
                                const pipeline_u8 *fragment, pipeline_u32 fragmentLen,
                                pipeline_u8 *out, pipeline_u32 outCap);

/*
 * pipeline_url_extract_fragment: the host-agnostic inverse of
 * pipeline_url_wrap() (spec #122): recovers everything after the FIRST `#`
 * byte in url[0 : urlLen], with NO comparison against any expected base URL
 * -- a frame wrapped around any base, on any host, extracts identically.
 * This is "split once on `#`", nothing more. fragmentOut must be at least
 * urlLen bytes (outCap is that bound, checked defensively). Returns
 * nonzero (true) and sets *fragmentLenOut on success. Returns 0 (false) --
 * writing nothing -- if url contains no `#` byte at all, or outCap is too
 * small for the remainder after it.
 */
int pipeline_url_extract_fragment(const pipeline_u8 *url, pipeline_u32 urlLen,
                                   pipeline_u8 *fragmentOut, pipeline_u32 outCap, pipeline_u32 *fragmentLenOut);

#endif /* PIPELINE_URL_H */
