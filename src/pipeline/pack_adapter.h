#ifndef PIPELINE_PACK_ADAPTER_H
#define PIPELINE_PACK_ADAPTER_H

/*
 * The pack/unpack adapters for the packed QR payload (spec #24, sub-issue
 * #26). Deliberately minimal: this sub-issue's job is to prove that the ROM
 * pack side and the host unpack side both derive their field layout from
 * the SAME generated format_descriptor.h (itself rendered from the single
 * JSON source src/pipeline/format_descriptor.json) -- not to implement the
 * real payload contents (serialize/sign, #28/#29) or QR encoding (#27).
 *
 * Like build_event.c/port_stub_c99.c, this file is pure: no MarioState, no
 * globals, no N64 headers. It is compiled a second time, unmodified, into
 * the host test tool (tools/pipeline_test).
 */

#include "build_event.h"
#include "format_descriptor.h"

#define PIPELINE_PACKED_SIZE PIPELINE_FMT_TOTAL_SIZE

/*
 * pipeline_pack: writes capture's fields and the given signature into out,
 * at the exact offsets/sizes format_descriptor.h describes. out must be at
 * least PIPELINE_PACKED_SIZE bytes.
 */
void pipeline_pack(const StarCapture *capture,
                    const pipeline_u8 sig[PIPELINE_FMT_SIZE_SIG],
                    pipeline_u8 out[PIPELINE_PACKED_SIZE]);

/*
 * pipeline_unpack: the inverse of pipeline_pack, reading fields back out of
 * a packed buffer at the same descriptor-derived offsets/sizes. Returns 0
 * on success, nonzero if in[0] isn't the expected PIPELINE_FMT_TAG_VALUE.
 */
int pipeline_unpack(const pipeline_u8 in[PIPELINE_PACKED_SIZE],
                     StarCapture *capture_out,
                     pipeline_u8 sig_out[PIPELINE_FMT_SIZE_SIG]);

#endif /* PIPELINE_PACK_ADAPTER_H */
