/*
 * See qr_cycle.h. Pure C89 (matching src/pipeline/'s, qr_render.c's, and
 * qr_display.c's own convention): no MarioState, no globals, no N64
 * headers, no <string.h>. Compiled unmodified into both the ROM build (src/
 * game is a SRC_DIRS entry) and, a second time, into tools/pipeline_test.
 */

#include "qr_cycle.h"

pipeline_u32 qr_cycle_frame_index(pipeline_u32 frameCount, pipeline_u32 tick) {
    pipeline_u32 count = (frameCount == 0u) ? 1u : frameCount;
    return (tick / QR_CYCLE_HOLD_TICKS) % count;
}
